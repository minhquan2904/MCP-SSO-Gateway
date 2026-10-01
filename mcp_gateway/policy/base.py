"""Policy contract and fail-closed wrapper."""

from __future__ import annotations

from enum import StrEnum
from typing import Protocol


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    UNAVAILABLE = "unavailable"


class PolicyProvider(Protocol):
    def check(self, issuer: str, subject: str, server_name: str) -> Decision: ...


class FailClosedPolicy:
    """Convert provider faults to a distinct unavailable decision."""

    def __init__(self, provider: PolicyProvider) -> None:
        self._provider = provider

    def check(self, issuer: str, subject: str, server_name: str) -> Decision:
        try:
            decision = self._provider.check(issuer, subject, server_name)
        except Exception:
            return Decision.UNAVAILABLE
        return decision if isinstance(decision, Decision) else Decision.UNAVAILABLE
