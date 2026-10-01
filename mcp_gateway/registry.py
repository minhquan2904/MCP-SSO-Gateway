"""Validated registry metadata loaded once at gateway startup."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from .config import ConfigError, read_secret_file

_NAME = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
_ALLOWED_FIELDS = frozenset(
    {
        "name",
        "client_name",
        "title",
        "description",
        "path",
        "kind",
        "upstream_token_file",
        "listed",
    }
)


@dataclass(frozen=True)
class ServerEntry:
    name: str
    client_name: str
    title: str
    description: str
    path: str
    kind: str
    upstream_token_file: Path | None
    listed: bool


class Registry:
    """Immutable lookup table with normalized non-overlapping path prefixes."""

    def __init__(self, entries: tuple[ServerEntry, ...]) -> None:
        self.entries = entries
        self._by_name = {entry.name: entry for entry in entries}

    def get(self, name: str) -> ServerEntry | None:
        return self._by_name.get(name)

    def __iter__(self):
        return iter(self.entries)


def _plain_string(value: object, label: str, path: Path) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"registry {path}: {label} must be a non-empty string")
    if any(ord(char) < 32 for char in value):
        raise ConfigError(f"registry {path}: {label} must not contain control characters")
    return value.strip()


def _server_path(value: object, source: Path) -> str:
    path = _plain_string(value, "path", source)
    parsed = urlsplit(path)
    if (
        parsed.scheme
        or parsed.netloc
        or parsed.query
        or parsed.fragment
        or not path.startswith("/")
        or not path.endswith("/")
        or "%" in path
        or "\\" in path
        or "//" in path
        or any(part in {".", ".."} for part in path.split("/"))
    ):
        raise ConfigError(
            f"registry {source}: path must be a canonical absolute trailing-slash prefix"
        )
    return path


def _token_path(value: object, source: Path, secrets_dir: Path, reserved: tuple[Path, ...]) -> Path:
    if not isinstance(value, str) or not value:
        raise ConfigError(f"registry {source}: upstream_token_file must be an absolute path")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ConfigError(f"registry {source}: upstream_token_file is invalid")
    try:
        relative = path.relative_to(secrets_dir)
        root = secrets_dir.resolve()
        target = path.resolve()
        target.relative_to(root)
        symlinked = any(
            (secrets_dir / Path(*relative.parts[:index])).is_symlink()
            for index in range(1, len(relative.parts) + 1)
        )
        reserved_targets = tuple(secret.resolve() for secret in reserved)
    except ValueError as exc:
        raise ConfigError(
            f"registry {source}: upstream_token_file must be below MCP_GATEWAY_SECRETS_DIR"
        ) from exc
    except (OSError, RuntimeError) as exc:
        raise ConfigError(f"registry {source}: upstream_token_file is invalid") from exc
    if not relative.parts or symlinked or target in reserved_targets:
        raise ConfigError(f"registry {source}: upstream_token_file is invalid")
    if not path.is_file() or not os.access(path, os.R_OK):
        raise ConfigError(f"registry {source}: upstream_token_file is not a readable regular file")
    return path


def load_registry(
    path: str | Path,
    *,
    secrets_dir: str | Path = "/run/secrets",
    reserved_secret_files: tuple[Path, ...] = (),
) -> Registry:
    """Load the normative schema and reject malformed or ambiguous routes."""
    source = Path(path)
    try:
        data = yaml.safe_load(source.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"registry {source}: file is not readable") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"registry {source}: invalid YAML") from exc
    if (
        not isinstance(data, dict)
        or set(data) != {"servers"}
        or not isinstance(data["servers"], list)
    ):
        raise ConfigError(f"registry {source}: requires exactly a servers list")
    if not data["servers"]:
        raise ConfigError(f"registry {source}: servers must not be empty")

    entries: list[ServerEntry] = []
    names: set[str] = set()
    client_names: set[str] = set()
    paths: list[str] = []
    secrets_root = Path(secrets_dir)
    for item in data["servers"]:
        if not isinstance(item, dict):
            raise ConfigError(f"registry {source}: each server must be a mapping")
        unknown = set(item) - _ALLOWED_FIELDS
        if unknown:
            raise ConfigError(f"registry {source}: unknown server field")
        required = {"name", "title", "description", "path", "kind"}
        if required - set(item):
            raise ConfigError(f"registry {source}: server is missing required fields")
        name = _plain_string(item["name"], "name", source)
        if not _NAME.fullmatch(name) or name in names:
            raise ConfigError(f"registry {source}: name must be unique and safe")
        client_name = _plain_string(item.get("client_name", name), "client_name", source)
        if not _NAME.fullmatch(client_name) or client_name in client_names:
            raise ConfigError(f"registry {source}: client_name must be unique and safe")
        route = _server_path(item["path"], source)
        if route in paths or any(
            route.startswith(existing) or existing.startswith(route) for existing in paths
        ):
            raise ConfigError(f"registry {source}: paths must be unique and non-overlapping")
        kind = item["kind"]
        if kind not in {"mcp", "http_api"}:
            raise ConfigError(f"registry {source}: kind must be mcp or http_api")
        has_token = "upstream_token_file" in item
        if kind == "mcp" and not has_token:
            raise ConfigError(f"registry {source}: kind mcp requires upstream_token_file")
        if kind == "http_api" and has_token:
            raise ConfigError(f"registry {source}: kind http_api forbids upstream_token_file")
        listed = item.get("listed", True)
        if not isinstance(listed, bool):
            raise ConfigError(f"registry {source}: listed must be boolean")
        token_file = (
            _token_path(item["upstream_token_file"], source, secrets_root, reserved_secret_files)
            if has_token
            else None
        )
        entries.append(
            ServerEntry(
                name,
                client_name,
                _plain_string(item["title"], "title", source),
                _plain_string(item["description"], "description", source),
                route,
                kind,
                token_file,
                listed,
            )
        )
        names.add(name)
        client_names.add(client_name)
        paths.append(route)
    return Registry(tuple(entries))


def read_upstream_token(entry: ServerEntry) -> str | None:
    """Read an upstream token only after authorization and URI binding succeed."""
    if entry.kind == "http_api":
        return None
    assert entry.upstream_token_file is not None
    return read_secret_file(entry.upstream_token_file, f"registry:{entry.name}")


def public_url(entry: ServerEntry, public_base_url: str) -> str:
    return f"{public_base_url.rstrip('/')}{entry.path}"
