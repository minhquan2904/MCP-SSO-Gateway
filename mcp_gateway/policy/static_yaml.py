"""Static YAML role/member policy loaded and validated at boot."""

from __future__ import annotations

from pathlib import Path

import yaml

from ..config import ConfigError
from ..registry import Registry
from .base import Decision


class StaticYamlPolicy:
    def __init__(self, path: str | Path, registry: Registry) -> None:
        source = Path(path)
        try:
            data = yaml.safe_load(source.read_text(encoding="utf-8"))
        except OSError as exc:
            raise ConfigError(f"policy {source}: file is not readable") from exc
        except yaml.YAMLError as exc:
            raise ConfigError(f"policy {source}: invalid YAML") from exc
        if not isinstance(data, dict) or set(data) != {"roles", "members"}:
            raise ConfigError(f"policy {source}: requires exactly roles and members mappings")
        roles_data = data["roles"]
        members_data = data["members"]
        if not isinstance(roles_data, dict) or not isinstance(members_data, dict):
            raise ConfigError(f"policy {source}: roles and members must be mappings")
        roles: dict[str, frozenset[str]] = {}
        for role, servers in roles_data.items():
            if (
                not isinstance(role, str)
                or not role
                or not isinstance(servers, list)
                or not all(isinstance(server, str) for server in servers)
            ):
                raise ConfigError(f"policy {source}: each role must map to a list of server names")
            unknown = set(servers) - {entry.name for entry in registry}
            if unknown:
                raise ConfigError(f"policy {source}: role grants an undeclared server")
            roles[role] = frozenset(servers)
        grants: dict[tuple[str, str], frozenset[str]] = {}
        for role, identities in members_data.items():
            if role not in roles:
                raise ConfigError(f"policy {source}: members references an undeclared role")
            if not isinstance(identities, list):
                raise ConfigError(f"policy {source}: each member role must be a list")
            for identity in identities:
                if (
                    not isinstance(identity, dict)
                    or set(identity) != {"issuer", "subject"}
                    or not all(
                        isinstance(identity[key], str) and identity[key] for key in identity
                    )
                ):
                    raise ConfigError(
                        f"policy {source}: members must contain exact issuer and subject mappings"
                    )
                key = (identity["issuer"], identity["subject"])
                grants[key] = grants.get(key, frozenset()) | roles[role]
        self._grants = grants

    def check(self, issuer: str, subject: str, server_name: str) -> Decision:
        granted = self._grants.get((issuer, subject), frozenset())
        return Decision.ALLOW if server_name in granted else Decision.DENY
