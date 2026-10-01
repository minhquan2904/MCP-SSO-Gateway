"""Structured hardening checks for the production and demo compose files.

Compose files are parsed with PyYAML (a runtime dependency) and checked as
data: network membership, published ports, secret mounts, environment, and
least-privilege runtime settings.
"""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath

import yaml

ROOT = Path(__file__).parents[1]
COMPOSE = ROOT / "deploy/docker-compose.example.yml"
SECRETS_DIR = PurePosixPath("/run/secrets")
UPSTREAMS = {"echo": "echo-net", "status": "status-net"}
# Volume -> the only services allowed to mount it (always read-only).
SECRET_VOLUMES = {
    "oidc-client": {"gateway"},
    "gateway-session": {"gateway"},
    "echo-token": {"gateway", "echo"},
    "nginx-tls": {"nginx"},
}
SECRET_KEY = re.compile(r"SECRET|TOKEN|PASSWORD|PRIVATE|CREDENTIAL", re.IGNORECASE)


def _compose(path: Path = COMPOSE) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _env(service: dict) -> dict[str, str]:
    env = service.get("environment") or {}
    if isinstance(env, list):
        env = dict(item.split("=", 1) for item in env)
    return {key: str(value) for key, value in env.items()}


def _networks(service: dict) -> set[str]:
    networks = service.get("networks") or []
    return set(networks if isinstance(networks, list) else networks.keys())


def _mounts(service: dict) -> list[tuple[str, PurePosixPath, bool]]:
    """(source, target, read_only) for every short- or long-syntax volume."""
    mounts = []
    for item in service.get("volumes") or []:
        if isinstance(item, str):
            parts = item.split(":")
            source, target = parts[0], parts[1]
            read_only = len(parts) > 2 and "ro" in parts[2].split(",")
        else:
            source, target = item.get("source", ""), item["target"]
            read_only = bool(item.get("read_only"))
        mounts.append((source, PurePosixPath(target), read_only))
    return mounts


def test_no_identity_provider_runs_and_only_nginx_publishes_loopback() -> None:
    services = _compose()["services"]
    assert set(services) == {"nginx", "gateway", *UPSTREAMS}
    assert not any("keycloak" in str(service.get("image", "")) for service in services.values())
    for name, service in services.items():
        if name != "nginx":
            assert "ports" not in service, name
            assert service.get("network_mode") is None, name
    ports = services["nginx"]["ports"]
    assert ports and all(str(port).startswith("127.0.0.1:") for port in ports)


def test_network_membership_isolates_authz_egress_and_each_upstream() -> None:
    data = _compose()
    services, networks = data["services"], data["networks"]
    members = {
        network: {name for name, service in services.items() if network in _networks(service)}
        for network in networks
    }
    assert set(networks) == {"edge", "authz", "idp-egress", *UPSTREAMS.values()}
    assert networks["authz"]["internal"] is True
    assert members["authz"] == {"nginx", "gateway"}
    assert not (networks["idp-egress"] or {}).get("internal")
    assert members["idp-egress"] == {"gateway"}
    assert members["edge"] == {"nginx"}
    for upstream, network in UPSTREAMS.items():
        assert networks[network]["internal"] is True
        assert members[network] == {"nginx", upstream}
        assert _networks(services[upstream]) == {network}
    assert _networks(services["gateway"]) == {"authz", "idp-egress"}


def test_gateway_config_uses_secret_files_https_idp_and_exact_callers() -> None:
    services = _compose()["services"]
    env = _env(services["gateway"])
    assert env["MCP_GATEWAY_INTROSPECT_CALLERS"] == "nginx"
    assert env["MCP_GATEWAY_OIDC_ISSUER"].startswith("https://idp.example.com")
    assert "MCP_GATEWAY_OIDC_DISCOVERY_URL" not in env
    assert env.get("MCP_GATEWAY_ALLOW_INSECURE_OIDC", "false") == "false"
    assert env["MCP_GATEWAY_PUBLIC_BASE_URL"] == "https://gateway.example.com"
    assert PurePosixPath(env["MCP_GATEWAY_SECRETS_DIR"]) == SECRETS_DIR
    for key in ("MCP_GATEWAY_OIDC_CLIENT_SECRET_FILE", "MCP_GATEWAY_SESSION_SECRET_FILE"):
        assert PurePosixPath(env[key]).is_relative_to(SECRETS_DIR)
    for name, service in services.items():
        for key, value in _env(service).items():
            if SECRET_KEY.search(key):
                assert key.endswith(("_FILE", "_DIR")), f"{name}.{key} must be a path key"
                assert PurePosixPath(value).is_absolute(), f"{name}.{key}"


def test_secret_volumes_are_directory_scoped_read_only_and_service_scoped() -> None:
    data = _compose()
    services = data["services"]
    assert set(SECRET_VOLUMES) <= set(data["volumes"])
    for name, service in services.items():
        for source, target, read_only in _mounts(service):
            if source in SECRET_VOLUMES:
                assert name in SECRET_VOLUMES[source], f"{name} must not mount {source}"
                assert read_only, f"{name}:{source} must be read-only"
                assert target.suffix == "", f"{name}:{source} must mount a directory"
            elif target.is_relative_to(SECRETS_DIR):
                raise AssertionError(f"{name} mounts unexpected secret source {source}")
    gateway_targets = {source: target for source, target, _ in _mounts(services["gateway"])}
    env = _env(services["gateway"])
    assert PurePosixPath(env["MCP_GATEWAY_OIDC_CLIENT_SECRET_FILE"]).parent == (
        gateway_targets["oidc-client"]
    )
    assert PurePosixPath(env["MCP_GATEWAY_SESSION_SECRET_FILE"]).parent == (
        gateway_targets["gateway-session"]
    )
    # Every gateway secret mount sits strictly below MCP_GATEWAY_SECRETS_DIR.
    for source in ("oidc-client", "gateway-session", "echo-token"):
        assert gateway_targets[source].parent == SECRETS_DIR
    # Status (http_api) receives no secret at all.
    assert not any(source in SECRET_VOLUMES for source, _, _ in _mounts(services["status"]))


def test_registry_upstream_tokens_resolve_inside_scoped_mounts() -> None:
    services = _compose()["services"]
    registry = yaml.safe_load((ROOT / "examples/registry.yaml").read_text(encoding="utf-8"))
    gateway_mounts = {target for _, target, _ in _mounts(services["gateway"])}
    for entry in registry["servers"]:
        if entry["kind"] != "mcp":
            assert "upstream_token_file" not in entry
            continue
        token = PurePosixPath(entry["upstream_token_file"])
        assert token.parent in gateway_mounts, entry["name"]
        assert token.is_relative_to(SECRETS_DIR)
    echo_file = PurePosixPath(_env(services["echo"])["ECHO_TOKEN_FILE"])
    echo_entry = next(entry for entry in registry["servers"] if entry["name"] == "echo")
    assert echo_file == PurePosixPath(echo_entry["upstream_token_file"])


def test_nginx_mounts_the_reference_server_and_all_snippets_read_only() -> None:
    nginx = _compose()["services"]["nginx"]
    mounts = {target: (source, read_only) for source, target, read_only in _mounts(nginx)}
    expected = {
        "/etc/nginx/conf.d/default.conf": "./nginx/default.conf",
        "/etc/nginx/snippets/mcp-gateway.locations.conf": "./nginx/mcp-gateway.locations.conf",
        "/etc/nginx/snippets/mcp-gateway-mcp.conf": "./nginx/mcp-gateway-mcp.conf",
        "/etc/nginx/snippets/mcp-gateway-http-api.conf": "./nginx/mcp-gateway-http-api.conf",
    }
    for target, source in expected.items():
        assert mounts[PurePosixPath(target)] == (source, True), target
        assert (COMPOSE.parent / source).is_file(), source


def test_every_service_runs_least_privilege_with_limits_and_healthchecks() -> None:
    services = _compose()["services"]
    for name, service in services.items():
        assert service["read_only"] is True, name
        assert service["security_opt"] == ["no-new-privileges:true"], name
        assert service["cap_drop"] == ["ALL"], name
        assert service.get("tmpfs"), name
        assert service.get("privileged") is not True, name
        assert service.get("mem_limit") and service.get("pids_limit") and service.get("cpus"), name
        test = service["healthcheck"]["test"]
        assert isinstance(test, list) and test[0] in {"CMD", "CMD-SHELL"} and len(test) > 1, name
    # Only the nginx master needs to switch to its worker user.
    assert set(services["nginx"].get("cap_add", [])) <= {"CHOWN", "SETGID", "SETUID"}
    for name in ("gateway", *UPSTREAMS):
        assert not services[name].get("cap_add"), name
        user = str(services[name]["user"]).split(":")[0]
        assert user not in {"", "0", "root"}, name
    gateway = services["gateway"]
    assert "/tmp" in gateway["tmpfs"]
    data_mounts = [m for m in _mounts(gateway) if m[1] == PurePosixPath("/data")]
    assert data_mounts == [("gateway-data", PurePosixPath("/data"), False)]


def test_image_runs_one_uvicorn_worker_as_non_root_without_proxy_headers() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    entrypoint = (ROOT / "docker/entrypoint.sh").read_text(encoding="utf-8")
    users = re.findall(r"(?m)^USER\s+(\S+)", dockerfile)
    assert users and users[-1] not in {"root", "0"}
    command = " ".join(entrypoint.split())
    assert re.search(r"--workers\s+1(\s|$)", command)
    assert "--no-proxy-headers" in command
    assert "--factory mcp_gateway.main:create_app" in command


def test_demo_only_nginx_publishes_loopback_http_port() -> None:
    services = _compose(ROOT / "demo/compose.yaml")["services"]
    assert set(services) == {
        "init-secrets",
        "keycloak",
        "init-keycloak-client",
        "gateway",
        "echo",
        "status",
        "nginx",
    }
    for name, service in services.items():
        if name != "nginx":
            assert not service.get("ports"), name
    assert services["nginx"]["ports"] == ["127.0.0.1:8080:8080"]


def test_demo_networks_isolate_services_and_initializers() -> None:
    data = _compose(ROOT / "demo/compose.yaml")
    services, networks = data["services"], data["networks"]
    expected = {
        "init-secrets": (set(), "none"),
        "init-keycloak-client": (set(), "service:keycloak"),
        "keycloak": ({"identity-provider"}, None),
        "gateway": ({"authz", "identity-provider"}, None),
        "echo": ({"echo-net"}, None),
        "status": ({"status-net"}, None),
        "nginx": ({"edge", "authz", "identity-provider", "echo-net", "status-net"}, None),
    }
    assert set(services) == set(expected)
    assert set(networks) == {"edge", "authz", "identity-provider", "echo-net", "status-net"}
    assert not (networks["edge"] or {}).get("internal")
    for name in set(networks) - {"edge"}:
        assert networks[name]["internal"] is True, name
    for name, (membership, mode) in expected.items():
        assert _networks(services[name]) == membership, name
        assert services[name].get("network_mode") == mode, name


def test_demo_secret_volumes_are_scoped_to_required_consumers() -> None:
    data = _compose(ROOT / "demo/compose.yaml")
    services = data["services"]
    # Bootstrap writers must mutate their volumes; runtime readers must not.
    expected = {
        "bootstrap-admin": {
            "init-secrets": False,
            "keycloak": True,
            "init-keycloak-client": False,
        },
        "oidc-client": {"init-secrets": False, "init-keycloak-client": True, "gateway": True},
        "gateway-session": {"init-secrets": False, "gateway": True},
        "echo-token": {"init-secrets": False, "gateway": True, "echo": True},
    }
    assert set(expected) <= set(data["volumes"])
    actual = {source: [] for source in expected}
    for name, service in services.items():
        for source, target, read_only in _mounts(service):
            if source in expected:
                assert target == SECRETS_DIR / source, f"{name}:{source}"
                actual[source].append((name, read_only))
            else:
                assert not target.is_relative_to(SECRETS_DIR), f"{name}:{source}"
    for source, consumers in expected.items():
        assert sorted(actual[source]) == sorted(consumers.items()), source


def test_demo_keycloak_proxy_pins_public_origin_and_remote_address() -> None:
    lines = (ROOT / "demo/idp-headers.conf").read_text(encoding="utf-8").splitlines()
    headers = {}
    for line in filter(str.strip, lines):
        directive, name, value = line.removesuffix(";").split()
        assert directive == "proxy_set_header" and line.endswith(";"), line
        assert name not in headers, f"duplicate {name}"
        headers[name] = value
    assert headers == {
        "Host": "localhost:8080",
        "X-Forwarded-For": "$remote_addr",
        "X-Forwarded-Host": "localhost:8080",
        "X-Forwarded-Proto": "http",
    }
