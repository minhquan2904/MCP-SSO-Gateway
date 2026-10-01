from __future__ import annotations

import re
from dataclasses import replace
from pathlib import Path

import pytest
from conftest import ALICE, BOB, DISCOVERY, EDGE_IP, ISSUER_A, ISSUER_B, signed_session
from starlette.testclient import TestClient

from mcp_gateway import cli
from mcp_gateway.main import create_app
from mcp_gateway.policy.static_yaml import StaticYamlPolicy
from mcp_gateway.registry import Registry
from mcp_gateway.tokens import make_identity


def run_cli(monkeypatch, env, *argv: str) -> int:
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return cli.main(list(argv))


def test_cli_issue_list_revoke_and_unauthorized_refusal(monkeypatch, capsys, config_files) -> None:
    code = run_cli(
        monkeypatch, config_files, "issue", "--issuer", ISSUER_A, "--subject", ALICE,
        "--label", "laptop",
    )
    out = capsys.readouterr().out
    assert code == 0 and re.search(r"mcpgw_[A-Za-z0-9_-]{43}_[0-9a-f]{8}", out)
    assert run_cli(monkeypatch, config_files, "list", "--issuer", ISSUER_A, "--subject", ALICE) == 0
    assert "mcpgw_" not in capsys.readouterr().out
    assert run_cli(
        monkeypatch, config_files, "issue", "--issuer", ISSUER_B, "--subject", ALICE,
        "--label", "laptop",
    ) == 1
    assert "not granted" in capsys.readouterr().err
    assert run_cli(
        monkeypatch, config_files, "revoke", "--issuer", ISSUER_A, "--subject", ALICE,
        "--label", "laptop",
    ) == 0


def test_session_cookie_attributes_and_token_page_output(make_client, store) -> None:
    client = make_client()
    identity = make_identity(ISSUER_A, ALICE)
    session = {
        "identity": {
            "issuer": identity.issuer,
            "subject": identity.subject,
            "identity_id": identity.identity_id,
        },
        "csrf": "csrf-value",
    }
    client.cookies.set("mcp_gateway_session", signed_session(session), path="/auth")
    page = client.get("/auth/token")
    assert page.status_code == 200 and "no-store" in page.headers["cache-control"]
    issued = client.post(
        "/auth/token", data={"csrf": "csrf-value", "label": "<script>alert(1)</script>"}
    )
    assert issued.status_code == 200
    assert "<script>alert(1)</script>" not in issued.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in issued.text
    token = re.search(r"mcpgw_[A-Za-z0-9_-]{43}_[0-9a-f]{8}", issued.text)
    assert token and "Bearer ${MCP_GATEWAY_TOKEN}" in issued.text
    assert issued.text.count(token.group(0)) == 1
    later = client.get("/auth/token")
    assert token.group(0) not in later.text


def test_cookie_is_scoped_httponly_lax_and_secure_from_public_url(make_client) -> None:
    response = make_client().get("/auth")
    assert response.status_code == 302
    cookie = response.headers["set-cookie"].lower()
    assert "path=/auth" in cookie
    assert "httponly" in cookie
    assert "samesite=lax" in cookie
    assert "secure" in cookie


def test_no_grant_user_sees_no_catalog_and_cannot_issue(make_client, store) -> None:
    client = make_client()
    identity = make_identity(ISSUER_A, BOB)
    client.cookies.set(
        "mcp_gateway_session",
        signed_session({
            "identity": {
                "issuer": identity.issuer,
                "subject": identity.subject,
                "identity_id": identity.identity_id,
            },
            "csrf": "csrf-value",
        }),
        path="/auth",
    )
    response = client.get("/auth/mcp")
    assert response.status_code == 200
    assert "Echo MCP" not in response.text
    assert "Status API" not in response.text

    page = client.get("/auth/token")
    assert page.status_code == 200 and "No server access" in page.text
    denied = client.post("/auth/token", data={"csrf": "csrf-value", "label": "forged"})
    assert denied.status_code == 403
    assert not re.search(r"mcpgw_[A-Za-z0-9_-]{43}_[0-9a-f]{8}", denied.text)
    assert store.list_active(identity.issuer, identity.subject) == []


def test_hidden_only_grant_can_issue_without_disclosing_server(
    cfg, registry, store, edge_callers, tmp_path: Path,
) -> None:
    hidden_registry = Registry(tuple(
        replace(entry, listed=False) if entry.name == "echo" else entry
        for entry in registry
    ))
    policy_file = tmp_path / "hidden-policy.yaml"
    policy_file.write_text(
        f'roles:\n  hidden-user: [echo]\nmembers:\n  hidden-user:\n'
        f'    - {{issuer: "{ISSUER_A}", subject: "{BOB}"}}\n',
        encoding="utf-8",
    )
    policy = StaticYamlPolicy(policy_file, hidden_registry)
    app = create_app(
        cfg, token_store=store, policy=policy, registry=hidden_registry,
        callers=edge_callers, discovery=DISCOVERY,
    )
    client = TestClient(
        app, base_url="https://gateway.example.com", client=(EDGE_IP, 50000),
        follow_redirects=False,
    )
    identity = make_identity(ISSUER_A, BOB)
    client.cookies.set(
        "mcp_gateway_session",
        signed_session({
            "identity": {
                "issuer": identity.issuer,
                "subject": identity.subject,
                "identity_id": identity.identity_id,
            },
            "csrf": "csrf-value",
        }),
        path="/auth",
    )

    home = client.get("/auth/token")
    assert home.status_code == 200
    assert "No server access" not in home.text
    catalog = client.get("/auth/mcp")
    assert catalog.status_code == 200
    assert "No servers are listed" in catalog.text
    assert "Echo MCP" not in catalog.text
    assert "/echo/" not in catalog.text
    assert "Status API" not in catalog.text

    issued = client.post("/auth/token", data={"csrf": "csrf-value", "label": "private"})
    assert issued.status_code == 200
    assert re.search(r"mcpgw_[A-Za-z0-9_-]{43}_[0-9a-f]{8}", issued.text)
    assert "Echo MCP" not in issued.text
    assert "&quot;echo&quot;" not in issued.text
    assert "Status API" not in issued.text


def test_healthz_does_not_echo_client_headers(make_client) -> None:
    response = make_client().get("/healthz", headers={"X-Probe": "secret-marker"})
    assert response.text == "ok" and "secret-marker" not in str(response.headers)


@pytest.mark.parametrize("path", ["/introspect-x", "/docs", "/openapi.json"])
def test_no_extra_public_surface(make_client, path: str) -> None:
    assert make_client().get(path).status_code == 404
