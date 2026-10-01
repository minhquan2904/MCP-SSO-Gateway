from __future__ import annotations

import re
import sqlite3

import pytest
from conftest import ALICE, ISSUER_A, ISSUER_B, NOW

from mcp_gateway.tokens import LabelInUseError, TokenStore, make_identity, token_is_well_formed


def test_identity_uses_issuer_and_subject_without_collision(store: TokenStore) -> None:
    first = store.issue(ISSUER_A, ALICE, "laptop", 3600)
    second = store.issue(ISSUER_B, ALICE, "laptop", 3600)
    assert first.identity_id != second.identity_id
    assert store.verify(first.token).issuer == ISSUER_A  # type: ignore[union-attr]
    assert store.verify(second.token).issuer == ISSUER_B  # type: ignore[union-attr]
    assert len(first.identity_id) == 43


def test_token_has_documented_format_and_checksum_is_checked_before_lookup(
    store: TokenStore, monkeypatch
) -> None:
    issued = store.issue(ISSUER_A, ALICE, "laptop", 3600)
    assert re.fullmatch(r"mcpgw_[A-Za-z0-9_-]{43}_[0-9a-f]{8}", issued.token)
    tampered = issued.token[:-1] + ("0" if issued.token[-1] != "0" else "1")
    monkeypatch.setattr(
        store, "_connect_read", lambda: pytest.fail("database lookup must not occur")
    )
    assert not token_is_well_formed(tampered)
    assert store.verify(tampered) is None


def test_expiry_and_revoke_make_tokens_unusable(tmp_path) -> None:
    clock = {"now": NOW}
    store = TokenStore(tmp_path / "tokens.sqlite3", now=lambda: clock["now"])
    issued = store.issue(ISSUER_A, ALICE, "laptop", 5)
    assert store.verify(issued.token) is not None
    clock["now"] += 5
    assert store.verify(issued.token) is None
    fresh = store.issue(ISSUER_A, ALICE, "laptop", 60)
    assert store.revoke(ISSUER_A, ALICE, "laptop") == 1
    assert store.verify(fresh.token) is None


def test_plaintext_is_never_persisted_and_schema_is_versioned(store: TokenStore, cfg) -> None:
    issued = store.issue(ISSUER_A, ALICE, "laptop", 3600)
    raw = cfg.db_path.read_bytes()
    assert issued.token.encode() not in raw
    assert issued.token.removeprefix("mcpgw_").encode() not in raw
    conn = sqlite3.connect(cfg.db_path)
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 1
        columns = {row[1] for row in conn.execute("PRAGMA table_info(personal_tokens)")}
    finally:
        conn.close()
    assert {"issuer", "subject", "identity_id", "token_sha256"} <= columns


def test_active_label_is_unique_per_identity_but_not_across_issuers(store: TokenStore) -> None:
    store.issue(ISSUER_A, ALICE, "laptop", 3600)
    with pytest.raises(LabelInUseError):
        store.issue(ISSUER_A, ALICE, "laptop", 3600)
    assert store.issue(ISSUER_B, ALICE, "laptop", 3600).identity_id == (
        make_identity(ISSUER_B, ALICE).identity_id
    )
