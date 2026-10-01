"""OIDC relying party: login, callback, and logout.

The discovery document is fetched and validated once when the application is
created; its `issuer` must equal the configured issuer, and the validated
document is pinned onto the authlib client so later requests cannot silently
switch metadata. The ID token `iss` claim is therefore validated against the
same configured issuer by authlib's claims validation.
"""

from __future__ import annotations

import logging
import secrets
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

import httpx
from authlib.integrations.base_client.errors import OAuthError
from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.responses import Response

from .config import Config
from .tokens import make_identity

log = logging.getLogger("mcp_gateway.oidc")

PROVIDER = "oidc"
_REQUIRED_ENDPOINTS = ("authorization_endpoint", "token_endpoint", "jwks_uri")
_SECURE_SCHEMES = frozenset({"https"})
_INSECURE_SCHEMES = frozenset({"http", "https"})
_DISCOVERY_TIMEOUT_SECONDS = 10.0


class OidcError(RuntimeError):
    """OIDC metadata or claim validation failure."""


class SubjectClaimMissing(Exception):
    """The validated ID token does not carry a usable `sub` claim."""


def fetch_discovery(
    discovery_url: str, issuer: str, *, allow_insecure: bool = False
) -> dict[str, Any]:
    """Fetch the discovery document over the back-channel and validate it."""
    try:
        response = httpx.get(discovery_url, timeout=_DISCOVERY_TIMEOUT_SECONDS)
        response.raise_for_status()
        metadata = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise OidcError(f"discovery document at {discovery_url} is unavailable") from exc
    validate_discovery(metadata, issuer, allow_insecure=allow_insecure)
    return metadata


def _absolute_url(value: object, schemes: frozenset[str]) -> bool:
    if not isinstance(value, str) or not value or value != value.strip():
        return False
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    return parsed.scheme in schemes and bool(parsed.netloc)


def validate_discovery(
    metadata: Mapping[str, Any], expected_issuer: str, *, allow_insecure: bool = False
) -> None:
    """Validate issuer and endpoints; plain HTTP endpoints need the insecure-demo flag."""
    if not isinstance(metadata, dict):
        raise OidcError("discovery document must be a JSON object")
    if metadata.get("issuer") != expected_issuer:
        raise OidcError("discovery document issuer does not match the configured issuer")
    schemes = _INSECURE_SCHEMES if allow_insecure else _SECURE_SCHEMES
    for field in _REQUIRED_ENDPOINTS:
        if not _absolute_url(metadata.get(field), schemes):
            raise OidcError(f"discovery document has invalid {field}")
    for field in ("userinfo_endpoint", "end_session_endpoint"):
        endpoint = metadata.get(field)
        if endpoint is not None and not _absolute_url(endpoint, schemes):
            raise OidcError(f"discovery document has invalid {field}")


def build_oauth(cfg: Config, metadata: Mapping[str, Any]) -> OAuth:
    """Validate the metadata, then register the client with it pinned in place."""
    validate_discovery(metadata, cfg.oidc_issuer, allow_insecure=cfg.allow_insecure_oidc)

    oauth = OAuth()
    kwargs: dict[str, Any] = dict(metadata)
    kwargs["client_id"] = cfg.oidc_client_id
    kwargs["client_secret"] = cfg.oidc_client_secret
    kwargs["client_kwargs"] = {"scope": "openid", "code_challenge_method": "S256"}
    oauth.register(name=PROVIDER, **kwargs)
    return oauth


def extract_subject(claims: Mapping[str, Any]) -> str:
    raw = claims.get("sub")
    if not isinstance(raw, str) or not raw.strip() or raw != raw.strip():
        raise SubjectClaimMissing("validated ID token has no usable 'sub' claim")
    return raw


def create_router(cfg: Config, oauth: OAuth) -> APIRouter:
    router = APIRouter()
    client = oauth.create_client(PROVIDER)
    assert client is not None

    @router.get("/auth")
    async def auth_start(request: Request) -> Response:
        # redirect_uri comes from configuration, never from request.url_for(),
        # which is built from the Host header.
        return await client.authorize_redirect(request, cfg.redirect_uri)

    @router.get("/auth/callback")
    async def auth_callback(request: Request) -> Response:
        try:
            token = await client.authorize_access_token(request)
        except OAuthError as exc:
            log.warning("OIDC callback failed: %s", exc.error or type(exc).__name__)
            return JSONResponse(
                status_code=400,
                content={
                    "error": exc.error or "oauth_error",
                    "detail": exc.description or str(exc),
                },
            )
        claims = token.get("userinfo")
        if not claims:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "subject_claim_missing",
                    "detail": "no validated ID token claims",
                },
            )
        try:
            subject = extract_subject(claims)
            identity = make_identity(cfg.oidc_issuer, subject)
        except (SubjectClaimMissing, ValueError) as exc:
            log.warning("cannot derive identity from ID token: %s", exc)
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_subject", "detail": str(exc)},
            )
        log.info("login succeeded for identity %s", identity.identity_id)
        request.session.clear()
        request.session["identity"] = {
            "issuer": identity.issuer,
            "subject": identity.subject,
            "identity_id": identity.identity_id,
        }
        request.session["csrf"] = secrets.token_urlsafe(32)
        return RedirectResponse("/auth/token", status_code=303)

    @router.get("/auth/logout")
    @router.post("/auth/logout")
    async def auth_logout(request: Request) -> Response:
        end_session = client.server_metadata.get("end_session_endpoint")
        request.session.clear()
        if end_session:
            return RedirectResponse(
                f"{end_session}?client_id={cfg.oidc_client_id}"
                f"&post_logout_redirect_uri={cfg.post_logout_redirect_uri}",
                status_code=303,
            )
        return RedirectResponse("/auth/logged-out", status_code=303)

    return router
