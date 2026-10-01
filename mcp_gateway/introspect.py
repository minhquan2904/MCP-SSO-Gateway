"""Internal bearer-token introspection endpoint for the nginx auth subrequest."""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Callable, Iterable
from urllib.parse import urlsplit

from fastapi import APIRouter, BackgroundTasks, Request
from fastapi.responses import JSONResponse, Response

from .audit import AuditLog
from .config import Config
from .policy.base import Decision, PolicyProvider
from .registry import Registry, read_upstream_token
from .tokens import TokenStore


def _resolve(host: str) -> set[str]:
    try:
        return {record[4][0] for record in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
    except OSError:
        return set()


class CallerAllowlist:
    """Hostname allowlist resolved to peers periodically; resolution failure denies."""

    def __init__(
        self,
        hosts: Iterable[str],
        *,
        ttl_seconds: float = 10.0,
        resolve: Callable[[str], set[str]] = _resolve,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._hosts = tuple(hosts)
        self._ttl_seconds = ttl_seconds
        self._resolve = resolve
        self._clock = clock
        self._lock = threading.Lock()
        self._addresses: frozenset[str] = frozenset()
        self._expires_at = float("-inf")

    def allows(self, peer: str | None) -> bool:
        if not peer:
            return False
        with self._lock:
            now = self._clock()
            if now >= self._expires_at:
                addresses: set[str] = set()
                for host in self._hosts:
                    addresses.update(self._resolve(host))
                self._addresses = frozenset(addresses)
                self._expires_at = now + self._ttl_seconds
            return peer in self._addresses


def parse_bearer(request: Request) -> str | None:
    value = request.headers.get("authorization", "")
    scheme, separator, token = value.partition(" ")
    if (
        scheme.lower() != "bearer"
        or separator != " "
        or not token
        or token != token.strip()
        or " " in token
    ):
        return None
    return token


def normalize_original_uri(value: str | None) -> str | None:
    """Return a canonical path or None for missing/ambiguous/or traversal input."""
    if not value or "\\" in value or "%" in value or "#" in value:
        return None
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc or parsed.fragment or not parsed.path.startswith("/"):
        return None
    path = parsed.path
    if "//" in path or any(segment in {".", ".."} for segment in path.split("/")):
        return None
    return path


def _bound_to_entry(path: str | None, entry_path: str) -> bool:
    return path is not None and path.startswith(entry_path)


def create_router(
    cfg: Config,
    store: TokenStore,
    policy: PolicyProvider,
    registry: Registry,
    audit: AuditLog,
    callers: CallerAllowlist | None = None,
) -> APIRouter:
    router = APIRouter()
    callers = callers or CallerAllowlist(cfg.introspect_callers)

    @router.get("/introspect")
    def introspect(request: Request, background: BackgroundTasks) -> Response:
        server_name = request.headers.get("x-mcp-gateway-server", "")
        original_uri = normalize_original_uri(request.headers.get("x-mcp-gateway-original-uri"))
        peer = request.client.host if request.client else None
        identity_id: str | None = None
        # Client headers are never persisted: audit only a registered server and
        # its configured path, and never attribute an untrusted peer's request.
        trusted_peer = False

        def done(response: Response, decision: str) -> Response:
            entry = registry.get(server_name) if trusted_peer else None
            bound = entry is not None and _bound_to_entry(original_uri, entry.path)
            audit.write(
                identity_id=identity_id,
                server=entry.name if entry else None,
                path=entry.path if bound else None,
                decision=decision,
                status=response.status_code,
            )
            return response

        # Must run before parsing or looking up a bearer token: a non-nginx peer
        # cannot use this route as an oracle or obtain an upstream credential.
        if not callers.allows(peer):
            return done(
                JSONResponse(status_code=403, content={"error": "forbidden_caller"}),
                "forbidden_caller",
            )
        trusted_peer = True

        token = parse_bearer(request)
        verified = store.verify(token) if token else None
        if verified is None:
            return done(
                JSONResponse(status_code=401, content={"error": "unauthorized"}),
                "unauthenticated",
            )
        identity_id = verified.identity_id
        background.add_task(store.mark_used, verified.token_sha256)

        entry = registry.get(server_name)
        if entry is None:
            return done(
                JSONResponse(status_code=404, content={"error": "unknown_server"}),
                "unknown_server",
            )
        # URI binding happens before policy and before reading a possibly sensitive
        # upstream token file. A location/registry drift therefore fails closed.
        if not _bound_to_entry(original_uri, entry.path):
            return done(
                JSONResponse(status_code=403, content={"error": "server_uri_mismatch"}),
                "server_uri_mismatch",
            )

        decision = policy.check(verified.issuer, verified.subject, entry.name)
        if decision is Decision.DENY:
            return done(JSONResponse(status_code=403, content={"error": "forbidden"}), "deny")
        if decision is not Decision.ALLOW:
            return done(
                JSONResponse(status_code=503, content={"error": "policy_unavailable"}),
                "unavailable",
            )

        try:
            upstream = read_upstream_token(entry)
        except Exception:
            return done(
                JSONResponse(status_code=503, content={"error": "upstream_token_unavailable"}),
                "unavailable",
            )
        headers = {"X-MCP-Gateway-User": verified.identity_id}
        if entry.kind == "mcp":
            assert upstream is not None
            headers["X-MCP-Gateway-Upstream-Token"] = upstream
        return done(Response(status_code=200, headers=headers), "allow")

    return router
