"""Shared fixtures with globally disabled sockets."""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import itsdangerous
import pytest
from starlette.testclient import TestClient

from mcp_gateway.config import Config, load_config
from mcp_gateway.introspect import CallerAllowlist
from mcp_gateway.main import create_app
from mcp_gateway.policy.static_yaml import StaticYamlPolicy
from mcp_gateway.registry import Registry, load_registry
from mcp_gateway.tokens import TokenStore

ISSUER_A = "https://idp.example.com/realms/mcp-demo"
ISSUER_B = "https://other-idp.example.com/realms/mcp-demo"
ALICE = "11111111-1111-4111-8111-111111111111"
BOB = "22222222-2222-4222-8222-222222222222"
EDGE_IP = "192.0.2.10"
OTHER_IP = "198.51.100.77"
NOW = 1_700_000_000
SESSION_SECRET = "0123456789abcdefghij0123456789abcdefghij"
UPSTREAM_TOKEN = "upstream-echo-token-value"

DISCOVERY = {
    "issuer": ISSUER_A,
    "authorization_endpoint": f"{ISSUER_A}/protocol/openid-connect/auth",
    "token_endpoint": f"{ISSUER_A}/protocol/openid-connect/token",
    "jwks_uri": f"{ISSUER_A}/protocol/openid-connect/certs",
    "end_session_endpoint": f"{ISSUER_A}/protocol/openid-connect/logout",
}

REGISTRY_YAML = """
servers:
  - name: echo
    client_name: echo
    title: Echo MCP
    description: Demo MCP server
    path: /echo/
    kind: mcp
    upstream_token_file: {token_file}
    listed: true
  - name: status-api
    title: Status API
    description: Demo HTTP API
    path: /status/
    kind: http_api
    listed: true
"""

POLICY_YAML = f"""
roles:
  developer: [echo]
  api-reader: [status-api]
members:
  developer:
    - {{issuer: "{ISSUER_A}", subject: "{ALICE}"}}
  api-reader:
    - {{issuer: "{ISSUER_A}", subject: "{ALICE}"}}
"""


@pytest.fixture()
def secrets_dir(tmp_path: Path) -> Path:
    root = tmp_path / "secrets"
    root.mkdir()
    return root


@pytest.fixture()
def env(tmp_path: Path, secrets_dir: Path) -> dict[str, str]:
    return {
        "MCP_GATEWAY_OIDC_ISSUER": ISSUER_A,
        "MCP_GATEWAY_OIDC_CLIENT_ID": "mcp-gateway",
        "MCP_GATEWAY_OIDC_CLIENT_SECRET": "client-secret-value-0123456789",
        "MCP_GATEWAY_SESSION_SECRET": SESSION_SECRET,
        "MCP_GATEWAY_PUBLIC_BASE_URL": "https://gateway.example.com",
        "MCP_GATEWAY_REGISTRY_FILE": str(tmp_path / "registry.yaml"),
        "MCP_GATEWAY_POLICY_FILE": str(tmp_path / "policy.yaml"),
        "MCP_GATEWAY_DATA_DIR": str(tmp_path / "data"),
        "MCP_GATEWAY_SECRETS_DIR": str(secrets_dir),
        "MCP_GATEWAY_INTROSPECT_CALLERS": "edge",
        "MCP_GATEWAY_TOKEN_TTL_DAYS": "90",
        "MCP_GATEWAY_AUDIT_MAX_BYTES": str(50 * 1024 * 1024),
        "MCP_GATEWAY_SESSION_TTL_SECONDS": "1800",
        "MCP_GATEWAY_DISPLAY_TZ": "UTC",
        "MCP_GATEWAY_LOG_LEVEL": "info",
    }


@pytest.fixture()
def token_file(secrets_dir: Path) -> Path:
    path = secrets_dir / "echo_token"
    path.write_text(UPSTREAM_TOKEN + "\n", encoding="utf-8")
    return path


@pytest.fixture()
def config_files(env: dict[str, str], token_file: Path) -> dict[str, str]:
    """Write a valid registry and policy to the paths named by `env`."""
    Path(env["MCP_GATEWAY_REGISTRY_FILE"]).write_text(
        REGISTRY_YAML.format(token_file=token_file), encoding="utf-8"
    )
    Path(env["MCP_GATEWAY_POLICY_FILE"]).write_text(POLICY_YAML, encoding="utf-8")
    return env


@pytest.fixture()
def cfg(config_files: dict[str, str]) -> Config:
    return load_config(config_files)


@pytest.fixture()
def registry(cfg: Config) -> Registry:
    return load_registry(
        cfg.registry_file,
        secrets_dir=cfg.secrets_dir,
        reserved_secret_files=cfg.reserved_secret_files,
    )


@pytest.fixture()
def policy(cfg: Config, registry: Registry) -> StaticYamlPolicy:
    return StaticYamlPolicy(cfg.policy_file, registry)


@pytest.fixture()
def store(cfg: Config) -> TokenStore:
    return TokenStore(cfg.db_path, now=lambda: NOW)


@pytest.fixture()
def edge_callers() -> CallerAllowlist:
    return CallerAllowlist(["edge"], resolve=lambda host: {EDGE_IP} if host == "edge" else set())


@pytest.fixture()
def make_client(
    cfg: Config,
    registry: Registry,
    policy: StaticYamlPolicy,
    store: TokenStore,
    edge_callers: CallerAllowlist,
) -> Callable[..., TestClient]:
    def build(
        *, peer: str = EDGE_IP, policy_override: Any = None, base_url: str | None = None
    ) -> TestClient:
        app = create_app(
            cfg,
            token_store=store,
            policy=policy_override or policy,
            registry=registry,
            callers=edge_callers,
            discovery=DISCOVERY,
        )
        return TestClient(
            app,
            base_url=base_url or "https://gateway.example.com",
            client=(peer, 50000),
            follow_redirects=False,
        )

    return build


def signed_session(data: dict[str, Any], secret: str = SESSION_SECRET) -> str:
    """Produce a session cookie value exactly as Starlette's SessionMiddleware signs it."""
    payload = base64.b64encode(json.dumps(data).encode("utf-8"))
    return itsdangerous.TimestampSigner(secret).sign(payload).decode("ascii")
