from __future__ import annotations

import pytest

from mcp_gateway.config import ConfigError, load_config


def test_config_requires_strong_session_secret_and_exact_hostnames(env) -> None:
    env["MCP_GATEWAY_SESSION_SECRET"] = "short"
    with pytest.raises(ConfigError, match="SESSION_SECRET"):
        load_config(env)
    env["MCP_GATEWAY_SESSION_SECRET"] = "0123456789abcdefghij0123456789abcdefghij"
    env["MCP_GATEWAY_INTROSPECT_CALLERS"] = "192.0.2.10"
    with pytest.raises(ConfigError, match="INTROSPECT_CALLERS"):
        load_config(env)
    env["MCP_GATEWAY_INTROSPECT_CALLERS"] = "192.0.2.0/24"
    with pytest.raises(ConfigError, match="INTROSPECT_CALLERS"):
        load_config(env)


def test_oidc_override_and_plain_http_require_explicit_demo_flag(env) -> None:
    env["MCP_GATEWAY_OIDC_DISCOVERY_URL"] = "https://discovery.example.com/openid"
    with pytest.raises(ConfigError, match="ALLOW_INSECURE"):
        load_config(env)
    env["MCP_GATEWAY_ALLOW_INSECURE_OIDC"] = "true"
    assert load_config(env).oidc_discovery_url == "https://discovery.example.com/openid"
