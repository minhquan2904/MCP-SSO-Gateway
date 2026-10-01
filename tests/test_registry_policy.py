from __future__ import annotations

import pytest
from conftest import REGISTRY_YAML

from mcp_gateway.config import ConfigError
from mcp_gateway.policy.base import Decision
from mcp_gateway.policy.static_yaml import StaticYamlPolicy
from mcp_gateway.registry import load_registry


@pytest.mark.parametrize(
    "fragment",
    [
        "unknown: value",
        "name: bad_name",
        "path: /echo",
        "kind: wrong",
    ],
)
def test_registry_rejects_schema_errors(tmp_path, secrets_dir, token_file, fragment: str) -> None:
    original = REGISTRY_YAML.format(token_file=token_file)
    path = tmp_path / "registry.yaml"
    path.write_text(
        original.replace("listed: true", f"listed: true\n    {fragment}", 1), encoding="utf-8"
    )
    with pytest.raises(ConfigError):
        load_registry(path, secrets_dir=secrets_dir)


def test_registry_rejects_overlapping_routes(tmp_path, secrets_dir, token_file) -> None:
    path = tmp_path / "registry.yaml"
    path.write_text(
        f"""servers:
  - name: echo
    title: Echo
    description: Test
    path: /echo/
    kind: mcp
    upstream_token_file: {token_file}
  - name: echo-child
    title: Child
    description: Test
    path: /echo/child/
    kind: mcp
    upstream_token_file: {token_file}
""",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="non-overlapping"):
        load_registry(path, secrets_dir=secrets_dir)

def test_registry_requires_token_file_for_mcp(tmp_path, secrets_dir) -> None:
    path = tmp_path / "registry.yaml"
    path.write_text(
        """servers:
  - name: echo
    title: Echo
    description: Test
    path: /echo/
    kind: mcp
""",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="requires upstream_token_file"):
        load_registry(path, secrets_dir=secrets_dir)


def test_registry_accepts_ordinary_token_file(tmp_path, secrets_dir, token_file) -> None:
    path = tmp_path / "registry.yaml"
    path.write_text(REGISTRY_YAML.format(token_file=token_file), encoding="utf-8")
    registry = load_registry(path, secrets_dir=secrets_dir)
    assert registry.get("echo").upstream_token_file == token_file


def test_registry_rejects_external_token_symlink(tmp_path, secrets_dir) -> None:
    outside = tmp_path / "outside_token"
    outside.write_text("outside-secret\n", encoding="utf-8")
    alias = secrets_dir / "outside_alias"
    alias.symlink_to(outside)
    path = tmp_path / "registry.yaml"
    path.write_text(REGISTRY_YAML.format(token_file=alias), encoding="utf-8")
    with pytest.raises(ConfigError, match="upstream_token_file"):
        load_registry(path, secrets_dir=secrets_dir)


@pytest.mark.parametrize("secret_name", ["session_secret", "client_secret"])
def test_registry_rejects_reserved_secret_symlink_alias(
    tmp_path, secrets_dir, secret_name: str
) -> None:
    reserved = secrets_dir / secret_name
    reserved.write_text("reserved-secret\n", encoding="utf-8")
    alias = secrets_dir / "upstream_alias"
    alias.symlink_to(reserved)
    path = tmp_path / "registry.yaml"
    path.write_text(REGISTRY_YAML.format(token_file=alias), encoding="utf-8")
    with pytest.raises(ConfigError, match="upstream_token_file"):
        load_registry(path, secrets_dir=secrets_dir, reserved_secret_files=(reserved,))


def test_registry_rejects_symlinked_token_directory(tmp_path, secrets_dir) -> None:
    token_dir = secrets_dir / "tokens"
    token_dir.mkdir()
    token = token_dir / "echo_token"
    token.write_text("upstream-secret\n", encoding="utf-8")
    alias = secrets_dir / "token_alias"
    alias.symlink_to(token_dir, target_is_directory=True)
    path = tmp_path / "registry.yaml"
    path.write_text(REGISTRY_YAML.format(token_file=alias / token.name), encoding="utf-8")
    with pytest.raises(ConfigError, match="upstream_token_file"):
        load_registry(path, secrets_dir=secrets_dir)


def test_http_api_cannot_have_upstream_token_and_never_reads_one(
    tmp_path, secrets_dir, token_file
) -> None:
    path = tmp_path / "registry.yaml"
    path.write_text(
        f"""servers:
  - name: status-api
    title: Status
    description: Test
    path: /status/
    kind: http_api
    upstream_token_file: {token_file}
""",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="forbids"):
        load_registry(path, secrets_dir=secrets_dir)


def test_static_policy_uses_exact_issuer_subject_and_rejects_undeclared_server(
    tmp_path, registry
) -> None:
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(
        """roles:
  member: [echo]
members:
  member:
    - issuer: https://idp.example.com/realms/mcp-demo
      subject: alice
""",
        encoding="utf-8",
    )
    policy = StaticYamlPolicy(policy_file, registry)
    assert policy.check(
        "https://idp.example.com/realms/mcp-demo", "alice", "echo"
    ) is Decision.ALLOW
    assert policy.check(
        "https://other-idp.example.com/realms/mcp-demo", "alice", "echo"
    ) is Decision.DENY
    policy_file.write_text("roles: {member: [missing]}\nmembers: {}\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="undeclared server"):
        StaticYamlPolicy(policy_file, registry)
