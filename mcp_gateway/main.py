"""ASGI application factory for MCP SSO Gateway.

`create_app()` is the only runtime construction point; importing this module
requires no environment variables. Registry, policy, and the OIDC discovery
document are validated once here; any failure aborts startup.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from starlette.middleware.sessions import SessionMiddleware

from . import introspect, oidc, token_page
from .audit import AuditLog
from .config import Config, load_config
from .policy.base import FailClosedPolicy, PolicyProvider
from .policy.static_yaml import StaticYamlPolicy
from .registry import Registry, load_registry
from .tokens import TokenStore

log = logging.getLogger("mcp_gateway")

SESSION_COOKIE = "mcp_gateway_session"
COOKIE_PATH = "/auth"


class CallbackQueryFilter(logging.Filter):
    """Strip the one-time authorization code from `/auth/callback` access logs."""

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and len(args) >= 3 and isinstance(args[2], str):
            path, separator, _ = args[2].partition("?")
            if separator and path == "/auth/callback":
                record.args = (*args[:2], path, *args[3:])
        return True


def _install_access_log_filter() -> None:
    access = logging.getLogger("uvicorn.access")
    if not any(isinstance(item, CallbackQueryFilter) for item in access.filters):
        access.addFilter(CallbackQueryFilter())


def create_app(
    config: Config | None = None,
    *,
    token_store: TokenStore | None = None,
    policy: PolicyProvider | None = None,
    registry: Registry | None = None,
    audit: AuditLog | None = None,
    callers: introspect.CallerAllowlist | None = None,
    discovery: Mapping[str, Any] | None = None,
) -> FastAPI:
    cfg = config or load_config()
    logging.basicConfig(
        level=getattr(logging, cfg.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    _install_access_log_filter()

    reg = registry or load_registry(
        cfg.registry_file,
        secrets_dir=cfg.secrets_dir,
        reserved_secret_files=cfg.reserved_secret_files,
    )
    policy_backend = FailClosedPolicy(policy or StaticYamlPolicy(cfg.policy_file, reg))
    store = token_store or TokenStore(cfg.db_path)
    audit_log = audit or AuditLog(cfg.data_dir, max_bytes=cfg.audit_max_bytes)
    metadata = dict(discovery) if discovery is not None else oidc.fetch_discovery(
        cfg.oidc_discovery_url,
        cfg.oidc_issuer,
        allow_insecure=cfg.allow_insecure_oidc,
    )

    app = FastAPI(title="MCP SSO Gateway", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.config = cfg
    app.state.registry = reg
    app.state.tokens = store
    app.state.audit = audit_log

    app.add_middleware(
        SessionMiddleware,
        secret_key=cfg.session_secret,
        session_cookie=SESSION_COOKIE,
        path=COOKIE_PATH,
        https_only=cfg.cookie_secure,
        same_site="lax",
        max_age=cfg.session_ttl_seconds,
    )

    app.include_router(oidc.create_router(cfg, oidc.build_oauth(cfg, metadata)))
    app.include_router(token_page.create_router(cfg, store, policy_backend, reg))
    app.include_router(
        introspect.create_router(cfg, store, policy_backend, reg, audit_log, callers)
    )

    @app.get("/healthz", response_class=PlainTextResponse)
    async def healthz() -> str:
        return "ok"

    return app
