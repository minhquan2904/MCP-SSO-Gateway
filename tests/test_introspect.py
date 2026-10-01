from __future__ import annotations

import json

from conftest import ALICE, BOB, EDGE_IP, ISSUER_A, OTHER_IP, UPSTREAM_TOKEN


def headers(
    token: str | None, server: str = "echo", uri: str | None = "/echo/mcp"
) -> dict[str, str]:
    result: dict[str, str] = {"X-MCP-Gateway-Server": server}
    if token is not None:
        result["Authorization"] = f"Bearer {token}"
    if uri is not None:
        result["X-MCP-Gateway-Original-URI"] = uri
    return result


def test_status_matrix_and_success_headers(make_client, store) -> None:
    alice = store.issue(ISSUER_A, ALICE, "laptop", 3600).token
    bob = store.issue(ISSUER_A, BOB, "laptop", 3600).token
    client = make_client()

    ok = client.get("/introspect", headers=headers(alice))
    assert ok.status_code == 200
    assert ok.headers["X-MCP-Gateway-Upstream-Token"] == UPSTREAM_TOKEN
    assert set(k.lower() for k in ok.headers if k.lower().startswith("x-mcp-gateway")) == {
        "x-mcp-gateway-user",
        "x-mcp-gateway-upstream-token",
    }
    api = client.get("/introspect", headers=headers(alice, "status-api", "/status/x"))
    assert api.status_code == 200
    assert "X-MCP-Gateway-Upstream-Token" not in api.headers
    assert client.get("/introspect", headers=headers(None)).status_code == 401
    assert client.get(
        "/introspect", headers={**headers(alice), "Authorization": "Basic x"}
    ).status_code == 401
    assert client.get("/introspect", headers=headers(bob)).status_code == 403
    assert client.get("/introspect", headers=headers(alice, "missing")).status_code == 404


def test_non_edge_peer_is_rejected_before_token_lookup(make_client, store, monkeypatch) -> None:
    token = store.issue(ISSUER_A, ALICE, "laptop", 3600).token
    monkeypatch.setattr(
        store, "verify", lambda value: (_ for _ in ()).throw(AssertionError("lookup"))
    )
    response = make_client(peer=OTHER_IP).get("/introspect", headers=headers(token))
    assert response.status_code == 403
    assert not any(k.lower().startswith("x-mcp-gateway") for k in response.headers)


def test_untrusted_server_headers_never_enter_audit(make_client, store, cfg) -> None:
    token = store.issue(ISSUER_A, ALICE, "laptop", 3600).token
    denied = make_client(peer=OTHER_IP).get(
        "/introspect", headers=headers(token, server=token, uri=f"/echo/{token}")
    )
    assert denied.status_code == 403

    unknown = make_client().get("/introspect", headers=headers(token, server=token))
    assert unknown.status_code == 404

    # A registered name remains useful for audit attribution, but a request URI
    # can carry sensitive client-controlled data after the configured prefix.
    allowed = make_client().get("/introspect", headers=headers(token, uri=f"/echo/{token}"))
    assert allowed.status_code == 200

    audit = "".join(path.read_text() for path in cfg.data_dir.glob("audit-*.jsonl"))
    records = {
        record["decision"]: record for record in map(json.loads, audit.splitlines())
    }
    assert token not in audit
    assert records["forbidden_caller"]["server"] is None
    assert records["forbidden_caller"]["path"] is None
    assert records["unknown_server"]["server"] is None
    assert records["allow"]["server"] == "echo" and records["allow"]["path"] == "/echo/"


def test_uri_server_mismatch_is_denied_before_upstream_token_read(
    make_client, store, monkeypatch
) -> None:
    import mcp_gateway.introspect as introspect

    token = store.issue(ISSUER_A, ALICE, "laptop", 3600).token
    monkeypatch.setattr(
        introspect, "read_upstream_token",
        lambda entry: (_ for _ in ()).throw(AssertionError("read")),
    )
    for uri in ("/status/x", "/echo/../status/x", "//echo/mcp", None):
        response = make_client().get("/introspect", headers=headers(token, uri=uri))
        assert response.status_code == 403


def test_policy_failure_and_unreadable_upstream_secret_are_503(
    make_client, store, token_file
) -> None:
    token = store.issue(ISSUER_A, ALICE, "laptop", 3600).token

    class Broken:
        def check(self, *_args):
            raise RuntimeError("backend down")

    assert make_client(policy_override=Broken()).get(
        "/introspect", headers=headers(token)
    ).status_code == 503
    token_file.unlink()
    assert make_client().get("/introspect", headers=headers(token)).status_code == 503


def test_audit_and_responses_do_not_contain_token_material(make_client, store, cfg) -> None:
    token = store.issue(ISSUER_A, ALICE, "laptop", 3600).token
    response = make_client().get("/introspect", headers=headers(token))
    assert token not in response.text
    audit = "".join(path.read_text() for path in cfg.data_dir.glob("audit-*.jsonl"))
    record = json.loads(audit.splitlines()[-1])
    assert record["identity_id"] and token not in audit and UPSTREAM_TOKEN not in audit
    assert "client_ip" not in record and EDGE_IP not in audit
