from __future__ import annotations

import pytest
from conftest import DISCOVERY, ISSUER_A

from mcp_gateway.config import load_config
from mcp_gateway.oidc import (
    OidcError,
    SubjectClaimMissing,
    build_oauth,
    extract_subject,
    validate_discovery,
)


def test_discovery_issuer_must_equal_configured_issuer() -> None:
    bad = dict(DISCOVERY, issuer="https://idp.example.com/other")
    with pytest.raises(OidcError, match="issuer"):
        validate_discovery(bad, ISSUER_A)


def test_id_token_subject_is_required_and_not_normalized() -> None:
    assert extract_subject({"sub": "alice@example"}) == "alice@example"
    with pytest.raises(SubjectClaimMissing, match="sub"):
        extract_subject({})
    with pytest.raises(SubjectClaimMissing, match="sub"):
        extract_subject({"sub": " alice@example "})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("authorization_endpoint", ""),
        ("authorization_endpoint", "relative/path"),
        ("token_endpoint", "ftp://idp.example.com/token"),
        ("jwks_uri", "https:///certs"),
        ("jwks_uri", " https://idp.example.com/certs"),
        ("token_endpoint", None),
    ],
)
def test_discovery_endpoints_must_be_absolute_http_urls(field: str, value: object) -> None:
    metadata = dict(DISCOVERY, **{field: value})
    with pytest.raises(OidcError, match=field):
        validate_discovery(metadata, ISSUER_A)


@pytest.mark.parametrize(
    "field",
    (
        "authorization_endpoint",
        "token_endpoint",
        "jwks_uri",
        "userinfo_endpoint",
        "end_session_endpoint",
    ),
)
def test_https_discovery_rejects_http_metadata_endpoint_in_production(
    field: str, env: dict[str, str]
) -> None:
    metadata = dict(DISCOVERY, **{field: "http://idp.example.com/endpoint"})
    with pytest.raises(OidcError, match=field):
        validate_discovery(metadata, ISSUER_A)
    with pytest.raises(OidcError, match=field):
        build_oauth(load_config(env), metadata)


@pytest.mark.parametrize(
    "field",
    (
        "authorization_endpoint",
        "token_endpoint",
        "jwks_uri",
        "userinfo_endpoint",
        "end_session_endpoint",
    ),
)
def test_insecure_demo_accepts_http_metadata_endpoint(field: str, env: dict[str, str]) -> None:
    env["MCP_GATEWAY_ALLOW_INSECURE_OIDC"] = "true"
    metadata = dict(DISCOVERY, **{field: "http://idp.example.com/endpoint"})
    validate_discovery(metadata, ISSUER_A, allow_insecure=True)
    assert build_oauth(load_config(env), metadata).create_client("oidc") is not None
