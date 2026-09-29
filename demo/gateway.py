"""MCP SSO Gateway, demo edition: the endpoint nginx calls with `auth_request`.

This file shows the core of the gateway in one place:

    personal token -> who is it? -> may they use this server? -> upstream token

It leaves out OIDC sign-in and the web UI. Tokens are issued from the command
line instead:

    python gateway.py issue <user> [label]
    python gateway.py revoke <user> <label>

`GET /introspect` answers nginx:

| Situation                                  | Status | Headers                          |
|--------------------------------------------|--------|----------------------------------|
| caller is not the nginx container          | 403    |                                  |
| missing, unknown, expired or revoked token | 401    |                                  |
| server name not in policy.yaml             | 404    |                                  |
| user not allowed on that server            | 403    | X-MCP-Gateway-User               |
| upstream token file unreadable             | 503    |                                  |
| allowed                                    | 200    | X-MCP-Gateway-User,              |
|                                            |        | X-MCP-Gateway-Upstream-Token     |
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import socket
import sqlite3
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import yaml
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

DB_PATH = Path(os.environ.get("GATEWAY_DB", "/data/tokens.db"))
POLICY_PATH = Path(os.environ.get("GATEWAY_POLICY", "/etc/gateway/policy.yaml"))
# DNS names of the only hosts allowed to call /introspect (the nginx container).
CALLERS = tuple(
    h.strip() for h in os.environ.get("GATEWAY_INTROSPECT_CALLERS", "nginx").split(",") if h.strip()
)
TOKEN_TTL_SECONDS = int(os.environ.get("GATEWAY_TOKEN_TTL_DAYS", "90")) * 86400
TOKEN_PREFIX = "mcpgw_"
# The subject ends up in a request header, so keep it boring.
SUBJECT_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


# ── tokens ──────────────────────────────────────────────────────────────────

def _sha256(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS tokens (
               sha256 TEXT PRIMARY KEY, subject TEXT NOT NULL, label TEXT NOT NULL,
               expires_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0)"""
    )
    return conn


def issue(subject: str, label: str) -> str:
    """Return a new token. Only its hash is stored, so this is the only time it exists."""
    if not SUBJECT_RE.match(subject):
        raise ValueError(f"invalid user name: {subject!r}")
    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    with _db() as conn:
        conn.execute(
            "INSERT INTO tokens (sha256, subject, label, expires_at) VALUES (?, ?, ?, ?)",
            (_sha256(token), subject, label, int(time.time()) + TOKEN_TTL_SECONDS),
        )
    return token


def revoke(subject: str, label: str) -> int:
    with _db() as conn:
        cur = conn.execute(
            "UPDATE tokens SET revoked = 1 WHERE subject = ? AND label = ? AND revoked = 0",
            (subject, label),
        )
        return cur.rowcount


def verify(token: str) -> str | None:
    """The subject of a live token, or None."""
    if not token.startswith(TOKEN_PREFIX):
        return None
    with _db() as conn:
        row = conn.execute(
            "SELECT subject FROM tokens WHERE sha256 = ? AND revoked = 0 AND expires_at > ?",
            (_sha256(token), int(time.time())),
        ).fetchone()
    return row[0] if row else None


# ── policy ──────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Server:
    users: frozenset[str]
    # None: the upstream has no auth of its own, so there is nothing to exchange.
    upstream_token_file: str | None


def load_policy(path: Path) -> dict[str, Server]:
    raw = yaml.safe_load(path.read_text()) or {}
    return {
        name: Server(frozenset(spec.get("users") or ()), spec.get("upstream_token_file"))
        for name, spec in (raw.get("servers") or {}).items()
    }


def read_upstream_token(path: str) -> str:
    """Read on every request, so rotating the upstream token needs no restart here."""
    value = Path(path).read_text().strip()
    if not value or "\n" in value:
        raise ValueError(f"{path} must hold exactly one non-empty line")
    return value


# ── who may call /introspect ────────────────────────────────────────────────

class CallerAllowlist:
    """Addresses of the nginx container, resolved from its DNS name.

    A 200 from /introspect carries the upstream secret. Every container on the
    same network can reach this service, so without this check anyone holding a
    valid personal token could ask for the upstream secret directly. The peer
    address comes from the TCP connection, never from a header (uvicorn runs with
    --no-proxy-headers). Names are re-resolved every `ttl` seconds because a
    recreated container keeps its name but gets a new address.
    """

    def __init__(self, hosts: tuple[str, ...], ttl: float = 10.0) -> None:
        self._hosts = hosts
        self._ttl = ttl
        self._lock = threading.Lock()
        self._addresses: frozenset[str] = frozenset()
        self._expires = float("-inf")

    @staticmethod
    def _resolve(host: str) -> set[str]:
        try:
            return {info[4][0] for info in socket.getaddrinfo(host, None)}
        except OSError:
            return set()  # fail closed

    def allows(self, peer: str | None) -> bool:
        with self._lock:
            if time.monotonic() >= self._expires:
                self._addresses = frozenset().union(*(self._resolve(h) for h in self._hosts))
                self._expires = time.monotonic() + self._ttl
            return peer is not None and peer in self._addresses


# ── the endpoint ────────────────────────────────────────────────────────────

def create_app() -> FastAPI:
    policy = load_policy(POLICY_PATH)
    callers = CallerAllowlist(CALLERS)
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/healthz")
    def healthz() -> dict:
        return {"ok": True}

    # Sync route: SQLite and file reads block, so FastAPI runs this in a thread.
    @app.get("/introspect")
    def introspect(request: Request) -> Response:
        # Before looking at the token, so a stranger cannot use this to test tokens.
        if not callers.allows(request.client.host if request.client else None):
            return JSONResponse({"error": "forbidden_caller"}, status_code=403)

        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        subject = verify(token.strip()) if scheme.lower() == "bearer" else None
        if subject is None:
            return JSONResponse({"error": "unauthorized"}, status_code=401)

        # Set by nginx per location, never taken from the client: otherwise a
        # client could pick which server it is checked against.
        name = request.headers.get("x-mcp-gateway-server", "")
        server = policy.get(name)
        if server is None:
            return JSONResponse({"error": "unknown_server"}, status_code=404)
        if subject not in server.users:
            return JSONResponse({"error": "forbidden", "server": name}, status_code=403,
                                headers={"X-MCP-Gateway-User": subject})

        headers = {"X-MCP-Gateway-User": subject}
        if server.upstream_token_file:
            try:
                headers["X-MCP-Gateway-Upstream-Token"] = read_upstream_token(
                    server.upstream_token_file)
            except (OSError, ValueError):
                return JSONResponse({"error": "upstream_token_unavailable"}, status_code=503)
        return Response(status_code=200, headers=headers)

    return app


def _cli(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[0] == "issue":
        print(issue(argv[1], argv[2] if len(argv) > 2 else "default"))
        return 0
    if len(argv) == 3 and argv[0] == "revoke":
        print(f"revoked {revoke(argv[1], argv[2])} token(s)")
        return 0
    print("usage: python gateway.py issue <user> [label]\n"
          "       python gateway.py revoke <user> <label>", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
