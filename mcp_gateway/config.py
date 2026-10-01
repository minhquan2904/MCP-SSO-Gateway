"""Immutable, fail-loud MCP SSO Gateway configuration.

Configuration is read once by `load_config()` (called from the app factory or
the CLI, never at import time). Every error names only the offending key, never
a value, so a misconfigured secret cannot leak into logs.
"""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

_PLACEHOLDERS = frozenset({"__FROM_VAULT__", "__FROM_PROBE__", "__FROM_OPERATOR__"})
_MIN_SESSION_SECRET_BYTES = 32
_DEFAULT_SECRETS_DIR = "/run/secrets"


class ConfigError(RuntimeError):
    """Configuration failure. Messages name keys and never include values."""


def read_secret_file(path: str | Path, key: str) -> str:
    """Read a one-line UTF-8 secret file, stripping exactly one trailing newline."""
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise ConfigError(f"{key}: secret file is not readable") from exc
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConfigError(f"{key}: secret file must be UTF-8") from exc
    if value.endswith("\r\n"):
        value = value[:-2]
    elif value.endswith("\n"):
        value = value[:-1]
    if not value.strip() or "\r" in value or "\n" in value:
        raise ConfigError(f"{key}: secret file must contain exactly one non-empty line")
    if value in _PLACEHOLDERS:
        raise ConfigError(f"{key}: secret file still contains a placeholder")
    return value


def _required(env: Mapping[str, str], key: str) -> str:
    value = env.get(key, "").strip()
    if not value:
        raise ConfigError(f"{key}: required")
    if value in _PLACEHOLDERS:
        raise ConfigError(f"{key}: placeholder value is not allowed")
    return value


def _secret(env: Mapping[str, str], key: str) -> str:
    """`<key>_FILE` wins; a direct env value is accepted for tests and local runs."""
    file_path = env.get(f"{key}_FILE", "").strip()
    if file_path:
        return read_secret_file(file_path, key)
    value = env.get(key, "")
    if not value.strip():
        raise ConfigError(f"{key}: required (set {key}_FILE)")
    if value in _PLACEHOLDERS:
        raise ConfigError(f"{key}: placeholder value is not allowed")
    return value


def _int(env: Mapping[str, str], key: str, default: int) -> int:
    raw = env.get(key, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{key}: must be a positive integer") from exc
    if value <= 0:
        raise ConfigError(f"{key}: must be a positive integer")
    return value


def _http_url(env: Mapping[str, str], key: str) -> str:
    value = _required(env, key).rstrip("/")
    return _check_http_url(value, key, allow_path=True)


def _check_http_url(value: str, key: str, *, allow_path: bool) -> str:
    parsed = urlparse(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
    ):
        raise ConfigError(
            f"{key}: must be an absolute HTTP(S) URL without credentials, query, or fragment"
        )
    if not allow_path and parsed.path not in {"", "/"}:
        raise ConfigError(f"{key}: must not include a path")
    return value


def _hostnames(env: Mapping[str, str], key: str) -> tuple[str, ...]:
    values = tuple(item.strip() for item in _required(env, key).split(",") if item.strip())
    if not values:
        raise ConfigError(f"{key}: must contain at least one hostname")
    for host in values:
        if "/" in host:
            raise ConfigError(f"{key}: CIDR ranges are not allowed; list exact hostnames")
        try:
            ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            pass
        else:
            raise ConfigError(f"{key}: IP addresses are not allowed; list exact hostnames")
        if any(ch in host for ch in " \t*?:@") or host.startswith(("-", ".")) or host.endswith("."):
            raise ConfigError(f"{key}: '{host}' is not an exact hostname")
    return values


def _absolute_path(env: Mapping[str, str], key: str) -> Path:
    path = Path(_required(env, key))
    if not path.is_absolute() or ".." in path.parts:
        raise ConfigError(f"{key}: must be an absolute path without '..'")
    return path


def _display_tz(env: Mapping[str, str]) -> str:
    name = env.get("MCP_GATEWAY_DISPLAY_TZ", "").strip() or "UTC"
    if name != "UTC":
        try:
            ZoneInfo(name)
        except (ZoneInfoNotFoundError, ValueError, OSError) as exc:
            raise ConfigError("MCP_GATEWAY_DISPLAY_TZ: unknown IANA time zone") from exc
    return name


def _bool(env: Mapping[str, str], key: str) -> bool:
    raw = env.get(key, "").strip().lower()
    if raw in {"", "false"}:
        return False
    if raw == "true":
        return True
    raise ConfigError(f"{key}: must be 'true' or 'false'")


@dataclass(frozen=True)
class Config:
    oidc_issuer: str
    oidc_discovery_url: str
    allow_insecure_oidc: bool
    oidc_client_id: str
    oidc_client_secret: str
    session_secret: str
    public_base_url: str
    registry_file: Path
    policy_file: Path
    data_dir: Path
    secrets_dir: Path
    reserved_secret_files: tuple[Path, ...]
    introspect_callers: tuple[str, ...]
    token_ttl_days: int
    audit_max_bytes: int
    session_ttl_seconds: int
    display_tz: str
    log_level: str

    @property
    def cookie_secure(self) -> bool:
        """Derived from the public base URL, never from the request scheme."""
        return urlparse(self.public_base_url).scheme == "https"

    @property
    def redirect_uri(self) -> str:
        return f"{self.public_base_url}/auth/callback"

    @property
    def post_logout_redirect_uri(self) -> str:
        return f"{self.public_base_url}/auth/logged-out"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "mcp-gateway.sqlite3"


def load_config(environ: Mapping[str, str] | None = None) -> Config:
    """Read and validate every startup setting exactly once."""
    env = os.environ if environ is None else environ

    issuer = _http_url(env, "MCP_GATEWAY_OIDC_ISSUER")
    default_discovery = f"{issuer}/.well-known/openid-configuration"
    discovery = env.get("MCP_GATEWAY_OIDC_DISCOVERY_URL", "").strip() or default_discovery
    _check_http_url(discovery, "MCP_GATEWAY_OIDC_DISCOVERY_URL", allow_path=True)
    allow_insecure = _bool(env, "MCP_GATEWAY_ALLOW_INSECURE_OIDC")
    if not allow_insecure:
        if urlparse(issuer).scheme != "https":
            raise ConfigError(
                "MCP_GATEWAY_OIDC_ISSUER: must use https unless "
                "MCP_GATEWAY_ALLOW_INSECURE_OIDC=true"
            )
        if urlparse(discovery).scheme != "https":
            raise ConfigError(
                "MCP_GATEWAY_OIDC_DISCOVERY_URL: must use https unless "
                "MCP_GATEWAY_ALLOW_INSECURE_OIDC=true"
            )
        if discovery != default_discovery:
            raise ConfigError(
                "MCP_GATEWAY_OIDC_DISCOVERY_URL: override requires "
                "MCP_GATEWAY_ALLOW_INSECURE_OIDC=true"
            )

    public_base_url = _http_url(env, "MCP_GATEWAY_PUBLIC_BASE_URL")
    if urlparse(public_base_url).path not in {"", "/"}:
        raise ConfigError("MCP_GATEWAY_PUBLIC_BASE_URL: must not include a path")

    session_secret = _secret(env, "MCP_GATEWAY_SESSION_SECRET")
    strength = sum(len(ch.encode("utf-8")) for ch in session_secret if not ch.isspace())
    if strength < _MIN_SESSION_SECRET_BYTES:
        raise ConfigError(
            f"MCP_GATEWAY_SESSION_SECRET: must contain at least {_MIN_SESSION_SECRET_BYTES} "
            "non-whitespace UTF-8 bytes"
        )

    secrets_dir = Path(env.get("MCP_GATEWAY_SECRETS_DIR", "").strip() or _DEFAULT_SECRETS_DIR)
    if not secrets_dir.is_absolute() or ".." in secrets_dir.parts:
        raise ConfigError("MCP_GATEWAY_SECRETS_DIR: must be an absolute path without '..'")

    reserved = tuple(
        Path(env[key].strip())
        for key in ("MCP_GATEWAY_SESSION_SECRET_FILE", "MCP_GATEWAY_OIDC_CLIENT_SECRET_FILE")
        if env.get(key, "").strip()
    )

    return Config(
        oidc_issuer=issuer,
        oidc_discovery_url=discovery,
        allow_insecure_oidc=allow_insecure,
        oidc_client_id=_required(env, "MCP_GATEWAY_OIDC_CLIENT_ID"),
        oidc_client_secret=_secret(env, "MCP_GATEWAY_OIDC_CLIENT_SECRET"),
        session_secret=session_secret,
        public_base_url=public_base_url,
        registry_file=_absolute_path(env, "MCP_GATEWAY_REGISTRY_FILE"),
        policy_file=_absolute_path(env, "MCP_GATEWAY_POLICY_FILE"),
        data_dir=_absolute_path(env, "MCP_GATEWAY_DATA_DIR"),
        secrets_dir=secrets_dir,
        reserved_secret_files=reserved,
        introspect_callers=_hostnames(env, "MCP_GATEWAY_INTROSPECT_CALLERS"),
        token_ttl_days=_int(env, "MCP_GATEWAY_TOKEN_TTL_DAYS", 90),
        audit_max_bytes=_int(env, "MCP_GATEWAY_AUDIT_MAX_BYTES", 50 * 1024 * 1024),
        session_ttl_seconds=_int(env, "MCP_GATEWAY_SESSION_TTL_SECONDS", 1800),
        display_tz=_display_tz(env),
        log_level=env.get("MCP_GATEWAY_LOG_LEVEL", "").strip() or "info",
    )
