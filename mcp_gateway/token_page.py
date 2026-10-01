"""`/auth/token`, `/auth/revoke`, `/auth/mcp` — the personal-token web UI."""

from __future__ import annotations

import html
import logging
import secrets
from datetime import datetime
from urllib.parse import parse_qs
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.concurrency import run_in_threadpool
from starlette.responses import Response

from . import pages
from .config import Config
from .policy.base import Decision, PolicyProvider
from .registry import Registry, public_url
from .tokens import LabelInUseError, TokenStore

log = logging.getLogger("mcp_gateway.token_page")

_NO_STORE = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "frame-ancestors 'none'",
}
_MAX_FORM_BYTES = 4096

_OS_HINTS = (("iphone", "iphone"), ("ipad", "ipad"), ("android", "android"),
             ("macintosh", "mac"), ("windows", "windows"), ("linux", "linux"))
_BROWSER_HINTS = (("edg/", "edge"), ("firefox/", "firefox"), ("chrome/", "chrome"),
                   ("safari/", "safari"))


def suggest_label(user_agent: str) -> str:
    ua = user_agent.lower()
    os_name = next((name for key, name in _OS_HINTS if key in ua), None)
    browser = next((name for key, name in _BROWSER_HINTS if key in ua), None)
    if os_name is None or browser is None:
        return "my-device"
    return f"{os_name}-{browser}"


def _page(
    title: str,
    main: str,
    status_code: int = 200,
    *,
    user: str | None = None,
    tab: str = "token",
) -> HTMLResponse:
    return HTMLResponse(
        pages.layout(title, main, user=user, tab=tab),
        status_code=status_code,
        headers=_NO_STORE,
    )


def _bad_session() -> HTMLResponse:
    return _page(
        "Invalid session",
        pages.error_view(
            "Invalid session",
            "This form is stale or your session changed. Reopen the token page and try again.",
            action_href="/auth/token",
            action_label="Reopen the token page",
        ),
        403,
    )


async def _form(request: Request) -> dict[str, str]:
    """Reads the body as a stream and stops early once it exceeds the size cap."""
    buffer = bytearray()
    async for chunk in request.stream():
        buffer += chunk
        if len(buffer) > _MAX_FORM_BYTES:
            return {}
    raw = buffer.decode("utf-8", errors="replace")
    return {key: values[0] for key, values in parse_qs(raw, keep_blank_values=True).items()}


def create_router(
    cfg: Config, store: TokenStore, policy: PolicyProvider, registry: Registry
) -> APIRouter:
    router = APIRouter()
    ttl_seconds = cfg.token_ttl_days * 86400
    tz = ZoneInfo(cfg.display_tz)

    def fmt_time(ts: int | None) -> str:
        if ts is None:
            return "never"
        return datetime.fromtimestamp(ts, tz).strftime("%Y-%m-%d %H:%M %Z")

    def decisions(issuer: str, subject: str) -> dict[str, Decision]:
        return {
            entry.name: policy.check(issuer, subject, entry.name)
            for entry in registry
            if entry.listed
        }

    def allowed_servers(issuer: str, subject: str) -> list[str]:
        return [
            entry.name
            for entry in registry
            if policy.check(issuer, subject, entry.name) is Decision.ALLOW
        ]

    def csrf_ok(request: Request, form: dict[str, str]) -> bool:
        expected = request.session.get("csrf")
        return bool(expected) and secrets.compare_digest(
            form.get("csrf", "").encode(), expected.encode()
        )

    def session_identity(request: Request) -> dict[str, str] | None:
        identity = request.session.get("identity")
        if not identity or not request.session.get("csrf"):
            return None
        return identity

    _HERO = pages.hero("Personal access token", "Connect an MCP client from this device.")

    def home(
        request: Request,
        identity: dict[str, str],
        *,
        error_html: str = "",
        label: str | None = None,
        replace: bool = False,
        status_code: int = 200,
    ) -> HTMLResponse:
        csrf = request.session["csrf"]
        allowed = allowed_servers(identity["issuer"], identity["subject"])
        if allowed:
            if label is None:
                label = suggest_label(request.headers.get("user-agent", ""))
            main = pages.issue_card(csrf, label, replace=replace, error_html=error_html)
        else:
            main = pages.no_access_card(retry_url="/auth/token")
        rows = store.list_active(identity["issuer"], identity["subject"])
        main += pages.tokens_card(rows, csrf, fmt_time)
        return _page("Tokens", _HERO + main, status_code, user=identity["subject"])

    @router.get("/auth/mcp")
    def server_catalog(request: Request) -> Response:
        identity = session_identity(request)
        if identity is None:
            return RedirectResponse("/auth", status_code=303)
        decided = decisions(identity["issuer"], identity["subject"])
        items = [
            {
                "title": entry.title,
                "description": entry.description,
                "allowed": True,
                "url": public_url(entry, cfg.public_base_url),
            }
            for entry in registry
            if entry.listed and decided[entry.name] is Decision.ALLOW
        ]
        return _page("Servers", pages.catalog_view(items), user=identity["subject"], tab="mcp")

    @router.get("/auth/token")
    def token_home(request: Request) -> Response:
        identity = session_identity(request)
        if identity is None:
            return RedirectResponse("/auth", status_code=303)
        return home(request, identity)

    @router.get("/auth/logged-out")
    def logged_out() -> Response:
        return _page("Signed out", pages.logged_out_view())

    @router.post("/auth/token")
    async def token_issue(request: Request) -> Response:
        return await run_in_threadpool(do_issue, request, await _form(request))

    @router.post("/auth/revoke")
    async def token_revoke(request: Request) -> Response:
        return await run_in_threadpool(do_revoke, request, await _form(request))

    def do_issue(request: Request, form: dict[str, str]) -> Response:
        identity = session_identity(request)
        if identity is None:
            return RedirectResponse("/auth", status_code=303)
        if not csrf_ok(request, form):
            return _bad_session()

        allowed = allowed_servers(identity["issuer"], identity["subject"])
        if not allowed:
            main = _HERO + pages.no_access_card(retry_url="/auth/token")
            return _page("Tokens", main, 403, user=identity["subject"])

        label = form.get("label", "")
        try:
            issued = store.issue(
                identity["issuer"], identity["subject"], label, ttl_seconds,
                replace=form.get("replace") == "1",
            )
        except LabelInUseError:
            error = pages.alert(
                f"Label <b>{html.escape(label)}</b> already has an active token. "
                "If this is the same device, check replace below; "
                "otherwise choose a different label."
            )
            return home(
                request, identity, error_html=error, label=label, replace=True, status_code=409
            )
        except ValueError as exc:
            error = pages.alert(html.escape(str(exc)))
            return home(request, identity, error_html=error, label=label[:64], status_code=400)

        log.info("token issued: identity=%s label=%s", issued.identity_id, issued.label)
        servers = {
            entry.client_name: public_url(entry, cfg.public_base_url)
            for entry in registry
            if entry.name in allowed and entry.listed
        }
        main = pages.issued_view(issued.label, fmt_time(issued.expires_at), issued.token, servers)
        return _page("Token issued", main, user=identity["subject"])

    def do_revoke(request: Request, form: dict[str, str]) -> Response:
        identity = session_identity(request)
        if identity is None:
            return RedirectResponse("/auth", status_code=303)
        if not csrf_ok(request, form):
            return _bad_session()
        label = form.get("label", "")
        count = store.revoke(identity["issuer"], identity["subject"], label)
        log.info(
            "token revoked: identity=%s label=%r count=%d",
            identity["identity_id"],
            label,
            count,
        )
        return RedirectResponse("/auth/token", status_code=303)

    return router
