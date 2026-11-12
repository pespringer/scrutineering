"""Operational contracts for backup, dashboard, tenancy, recovery, and SLOs."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


@dataclass(frozen=True)
class BackupRotation:
    keep: int = 7
    max_age_days: int = 30

    def validate(self) -> "BackupRotation":
        if self.keep < 1 or self.max_age_days < 1:
            raise ValueError("backup rotation values must be positive")
        return self


def rotate_backup_names(names: list[str], policy: BackupRotation) -> tuple[list[str], list[str]]:
    policy.validate()
    ordered = sorted(set(names), reverse=True)
    return ordered[:policy.keep], ordered[policy.keep:]


@dataclass(frozen=True)
class ExportCursor:
    value: int = 0
    page_size: int = 100

    def next(self, total: int) -> "ExportCursor | None":
        if self.value < 0 or not 1 <= self.page_size <= 5000:
            raise ValueError("invalid export cursor")
        value = self.value + self.page_size
        return None if value >= total else ExportCursor(value, self.page_size)


def filter_key(filters: dict[str, str | None]) -> str:
    return hashlib.sha256(json.dumps(filters, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:16]


@dataclass(frozen=True)
class QuarantineRecord:
    artifact_id: str
    reason: str
    expires_at: datetime

    def active(self, now: datetime | None = None) -> bool:
        current = now or datetime.now(timezone.utc)
        return self.expires_at > current


@dataclass(frozen=True)
class ResourceBudget:
    timeout_seconds: int = 600
    output_bytes: int = 2_000
    memory_mb: int = 1024
    cpu_seconds: int = 600

    def validate(self) -> "ResourceBudget":
        if min(self.timeout_seconds, self.output_bytes, self.memory_mb, self.cpu_seconds) < 1:
            raise ValueError("resource budget values must be positive")
        return self


def tenant_scope(actor_tenant: str | None, requested_tenant: str | None) -> bool:
    return bool(actor_tenant and requested_tenant and actor_tenant == requested_tenant)


@dataclass(frozen=True)
class RecoveryEscalation:
    severity: str
    attempts: int
    threshold: int = 3

    def needs_review(self) -> bool:
        if self.attempts < 0 or self.threshold < 1:
            raise ValueError("invalid escalation values")
        return self.attempts >= self.threshold or self.severity.upper() == "CRITICAL"


def slo_breach(latency_seconds: float, failure_rate: float, *, latency_limit: float = 300, failure_limit: float = 0.10) -> bool:
    return latency_seconds < 0 or failure_rate < 0 or latency_seconds > latency_limit or failure_rate > failure_limit
