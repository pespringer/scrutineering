"""Fail-closed remediation execution resilience contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


@dataclass(frozen=True)
class ExecutionLease:
    owner: str
    version: int
    expires_at: datetime

    def active(self, *, now: datetime | None = None) -> bool:
        current = now or datetime.now(timezone.utc)
        return self.expires_at > current

    def renew(self, owner: str, *, seconds: int = 300, now: datetime | None = None) -> "ExecutionLease":
        if owner != self.owner or seconds < 1 or not self.active(now=now):
            raise ValueError("execution lease cannot be renewed")
        current = now or datetime.now(timezone.utc)
        return ExecutionLease(owner, self.version + 1, current + timedelta(seconds=seconds))


@dataclass(frozen=True)
class RetryBudget:
    maximum_attempts: int = 3
    used_attempts: int = 0

    def consume(self) -> "RetryBudget":
        if self.maximum_attempts < 1 or self.used_attempts < 0:
            raise ValueError("invalid retry budget")
        if self.used_attempts >= self.maximum_attempts:
            raise ValueError("retry budget exhausted")
        return RetryBudget(self.maximum_attempts, self.used_attempts + 1)


@dataclass(frozen=True)
class ExecutionResourceBudget:
    timeout_seconds: int = 900
    memory_mb: int = 2048
    output_bytes: int = 5_000_000

    def validate(self) -> "ExecutionResourceBudget":
        if min(self.timeout_seconds, self.memory_mb, self.output_bytes) < 1:
            raise ValueError("execution resource budgets must be positive")
        return self


def quarantine_expired(expires_at: datetime, *, now: datetime | None = None) -> bool:
    current = now or datetime.now(timezone.utc)
    observed = expires_at.replace(tzinfo=timezone.utc) if expires_at.tzinfo is None else expires_at
    return observed <= current


def replay_allowed(*, state: str, approved: bool, lease_active: bool, artifact_fingerprint: str | None) -> bool:
    return state in {"approved", "failed", "blocked"} and approved and lease_active and bool(artifact_fingerprint)


def tenant_execution_capacity(active: int, limit: int) -> dict[str, object]:
    if active < 0 or limit < 1:
        raise ValueError("invalid tenant execution capacity")
    return {"active": active, "limit": limit, "available": max(0, limit - active), "admit": active < limit}
