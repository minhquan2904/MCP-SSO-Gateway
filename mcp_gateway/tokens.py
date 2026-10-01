"""Personal token store: identity derivation, issue, verify, revoke.

Token format: ``mcpgw_<43 base64url chars>_<8 hex chars>``. The trailing eight
characters are the first eight hex digits of SHA-256 over the ``mcpgw_<body>``
part, so a mistyped or truncated token is rejected before any database access.
Only the SHA-256 of the full token string is stored; plaintext exists only in
the ``IssuedToken`` returned to the caller.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import re
import secrets
import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger("mcp_gateway.tokens")

TOKEN_PREFIX = "mcpgw_"
_BODY_LEN = 43
_CHECKSUM_LEN = 8
_TOKEN_RE = re.compile(rf"mcpgw_[A-Za-z0-9_-]{{{_BODY_LEN}}}_[0-9a-f]{{{_CHECKSUM_LEN}}}")
_MAX_LABEL_LEN = 64
_MAX_ISSUER_LEN = 2048
_MAX_SUBJECT_LEN = 255
_WRITE_TIMEOUT_SECONDS = 5.0
_MARK_USED_TIMEOUT_SECONDS = 1.0
SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE personal_tokens (
    token_sha256 TEXT PRIMARY KEY,
    issuer       TEXT NOT NULL,
    subject      TEXT NOT NULL,
    identity_id  TEXT NOT NULL,
    label        TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    revoked_at   INTEGER,
    last_used_at INTEGER
);
CREATE INDEX idx_pt_identity ON personal_tokens(identity_id);
"""


class TokenStoreError(RuntimeError):
    """Token store operation failed. sqlite3 errors never escape this module."""


class LabelInUseError(TokenStoreError):
    """The identity already has an active token with this label."""


@dataclass(frozen=True)
class Identity:
    issuer: str
    subject: str
    identity_id: str


@dataclass(frozen=True)
class IssuedToken:
    """Result of `issue()`. `token` is plaintext and must only reach its recipient."""

    token: str
    identity_id: str
    label: str
    created_at: int
    expires_at: int


@dataclass(frozen=True)
class VerifiedToken:
    issuer: str
    subject: str
    identity_id: str
    label: str
    token_sha256: str
    expires_at: int


@dataclass(frozen=True)
class ActiveToken:
    label: str
    identity_id: str
    created_at: int
    last_used_at: int | None
    expires_at: int


def _checked(value: object, name: str, max_len: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    if value != value.strip():
        raise ValueError(f"{name} must not have surrounding whitespace")
    if len(value) > max_len:
        raise ValueError(f"{name} must be at most {max_len} characters")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise ValueError(f"{name} must not contain control characters")
    return value


def make_identity(issuer: str, subject: str) -> Identity:
    """Derive the canonical identity. Neither value is normalized."""
    issuer = _checked(issuer, "issuer", _MAX_ISSUER_LEN)
    subject = _checked(subject, "subject", _MAX_SUBJECT_LEN)
    digest = hashlib.sha256(issuer.encode() + b"\x00" + subject.encode()).digest()
    identity_id = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return Identity(issuer, subject, identity_id)


def _validate_label(label: str) -> str:
    if not isinstance(label, str) or not label.strip():
        raise ValueError("label must not be empty")
    label = label.strip()
    if len(label) > _MAX_LABEL_LEN:
        raise ValueError(f"label must be at most {_MAX_LABEL_LEN} characters")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in label):
        raise ValueError("label must not contain control characters")
    return label


def _validate_ttl(ttl_seconds: int) -> int:
    if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be a positive integer")
    return ttl_seconds


def _checksum(prefix_and_body: str) -> str:
    return hashlib.sha256(prefix_and_body.encode()).hexdigest()[:_CHECKSUM_LEN]


def _generate_token() -> str:
    body = secrets.token_urlsafe(32)
    assert len(body) == _BODY_LEN
    head = TOKEN_PREFIX + body
    return f"{head}_{_checksum(head)}"


def token_is_well_formed(token: object) -> bool:
    """Shape and checksum only; no database access."""
    if not isinstance(token, str) or not _TOKEN_RE.fullmatch(token):
        return False
    head, _, checksum = token.rpartition("_")
    return secrets.compare_digest(_checksum(head), checksum)


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class TokenStore:
    """SQLite store; a fresh connection per operation, schema tracked by user_version."""

    def __init__(self, db_path: str | Path, *, now: Callable[[], int] = lambda: int(time.time())):
        self._db_path = Path(db_path)
        self._now = now

    def _connect_write(self) -> sqlite3.Connection:
        try:
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(self._db_path), timeout=_WRITE_TIMEOUT_SECONDS)
            conn.isolation_level = None
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            if version == 0:
                has_table = conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='personal_tokens'"
                ).fetchone()
                if has_table:
                    conn.close()
                    raise TokenStoreError("token store has an unrecognized schema")
                conn.executescript(_SCHEMA + f"PRAGMA user_version = {SCHEMA_VERSION};")
            elif version != SCHEMA_VERSION:
                conn.close()
                raise TokenStoreError(f"token store schema version {version} is not supported")
        except (sqlite3.Error, OSError) as exc:
            raise TokenStoreError(f"token store is not writable: {type(exc).__name__}") from exc
        return conn

    def _connect_read(self) -> sqlite3.Connection | None:
        """Read-only connection; None when no database exists or it is not ours."""
        if not self._db_path.exists():
            return None
        try:
            conn = sqlite3.connect(
                f"file:{self._db_path}?mode=ro", uri=True, timeout=_WRITE_TIMEOUT_SECONDS
            )
            if conn.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
                conn.close()
                return None
        except sqlite3.Error:
            return None
        return conn

    def issue(
        self,
        issuer: str,
        subject: str,
        label: str,
        ttl_seconds: int,
        *,
        replace: bool = False,
    ) -> IssuedToken:
        identity = make_identity(issuer, subject)
        label = _validate_label(label)
        ttl_seconds = _validate_ttl(ttl_seconds)
        now = self._now()
        token = _generate_token()
        expires_at = now + ttl_seconds

        conn = self._connect_write()
        try:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT 1 FROM personal_tokens WHERE identity_id = ? AND label = ? "
                "AND revoked_at IS NULL AND expires_at > ?",
                (identity.identity_id, label, now),
            ).fetchone()
            if existing:
                if not replace:
                    conn.execute("ROLLBACK")
                    raise LabelInUseError("label already has an active token for this identity")
                conn.execute(
                    "UPDATE personal_tokens SET revoked_at = ? WHERE identity_id = ? "
                    "AND label = ? AND revoked_at IS NULL AND expires_at > ?",
                    (now, identity.identity_id, label, now),
                )
            conn.execute(
                "INSERT INTO personal_tokens (token_sha256, issuer, subject, identity_id, label, "
                "created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (_hash(token), identity.issuer, identity.subject, identity.identity_id, label, now,
                 expires_at),
            )
            conn.execute("COMMIT")
        except LabelInUseError:
            raise
        except sqlite3.Error as exc:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise TokenStoreError(f"token store is not writable: {type(exc).__name__}") from exc
        finally:
            conn.close()
        return IssuedToken(token, identity.identity_id, label, now, expires_at)

    def verify(self, token: object) -> VerifiedToken | None:
        """Read-only. Malformed or checksum-invalid tokens never reach the database."""
        if not token_is_well_formed(token):
            return None
        assert isinstance(token, str)
        conn = self._connect_read()
        if conn is None:
            return None
        token_sha256 = _hash(token)
        try:
            row = conn.execute(
                "SELECT token_sha256, issuer, subject, identity_id, label, expires_at, revoked_at "
                "FROM personal_tokens WHERE token_sha256 = ?",
                (token_sha256,),
            ).fetchone()
        except sqlite3.Error:
            return None
        finally:
            conn.close()
        if row is None:
            return None
        stored, issuer, subject, identity_id, label, expires_at, revoked_at = row
        if not secrets.compare_digest(stored, token_sha256):
            return None
        if revoked_at is not None or expires_at <= self._now():
            return None
        return VerifiedToken(issuer, subject, identity_id, label, token_sha256, expires_at)

    def list_active(
        self, issuer: str | None = None, subject: str | None = None
    ) -> list[ActiveToken]:
        """Active tokens for one identity, or for everyone when both are omitted."""
        if (issuer is None) != (subject is None):
            raise ValueError("issuer and subject must be given together")
        conn = self._connect_read()
        if conn is None:
            return []
        query = (
            "SELECT label, identity_id, created_at, last_used_at, expires_at FROM personal_tokens "
            "WHERE revoked_at IS NULL AND expires_at > ?"
        )
        params: list[object] = [self._now()]
        if issuer is not None and subject is not None:
            query += " AND identity_id = ?"
            params.append(make_identity(issuer, subject).identity_id)
        try:
            rows = conn.execute(
                query + " ORDER BY identity_id, label, created_at", params
            ).fetchall()
        except sqlite3.Error as exc:
            raise TokenStoreError(f"token store is not readable: {type(exc).__name__}") from exc
        finally:
            conn.close()
        return [ActiveToken(*row) for row in rows]

    def revoke(self, issuer: str, subject: str, label: str) -> int:
        identity = make_identity(issuer, subject)
        now = self._now()
        conn = self._connect_write()
        try:
            cursor = conn.execute(
                "UPDATE personal_tokens SET revoked_at = ? WHERE identity_id = ? AND label = ? "
                "AND revoked_at IS NULL AND expires_at > ?",
                (now, identity.identity_id, label, now),
            )
            return cursor.rowcount
        except sqlite3.Error as exc:
            raise TokenStoreError(f"token store is not writable: {type(exc).__name__}") from exc
        finally:
            conn.close()

    def mark_used(self, token_sha256: str) -> None:
        """Best-effort `last_used_at` update. Never raises; never logs the hash."""
        try:
            conn = sqlite3.connect(
                f"file:{self._db_path}?mode=rw", uri=True, timeout=_MARK_USED_TIMEOUT_SECONDS
            )
        except sqlite3.Error as exc:
            log.warning("mark_used: cannot open database (%s)", type(exc).__name__)
            return
        try:
            conn.execute(
                "UPDATE personal_tokens SET last_used_at = ? WHERE token_sha256 = ?",
                (self._now(), token_sha256),
            )
            conn.commit()
        except Exception as exc:  # noqa: BLE001 - best-effort by design
            log.warning("mark_used: update failed (%s)", type(exc).__name__)
        finally:
            try:
                conn.close()
            except sqlite3.Error:
                pass
