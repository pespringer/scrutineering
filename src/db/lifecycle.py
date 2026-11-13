"""Database archive, retention, growth, and backup deletion contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


@dataclass(frozen=True)
class ArchivePolicy:
    days: int = 365
    enabled: bool = False

    def cutoff(self, now: datetime | None = None) -> datetime:
        if self.days < 1:
            raise ValueError("archive days must be positive")
        return (now or datetime.now(timezone.utc)) - timedelta(days=self.days)


def archive_candidates(records: list[dict], *, timestamp_key: str, policy: ArchivePolicy, now: datetime | None = None) -> list[dict]:
    cutoff = policy.cutoff(now)
    result = []
    for record in records:
        observed = record.get(timestamp_key)
        if not isinstance(observed, datetime):
            continue
        if observed.tzinfo is None:
            observed = observed.replace(tzinfo=timezone.utc)
        if observed < cutoff:
            result.append(record)
    return result


def tenant_retention(tenant: str, requested_days: int, *, minimum_days: int = 7, maximum_days: int = 3650) -> dict[str, object]:
    if not tenant or not minimum_days <= requested_days <= maximum_days:
        raise ValueError("tenant retention is outside the permitted range")
    return {"tenant": tenant, "days": requested_days, "purge_enabled": False}


def growth_report(*, current_bytes: int, previous_bytes: int, interval_days: int) -> dict[str, float | int]:
    if min(current_bytes, previous_bytes) < 0 or interval_days < 1:
        raise ValueError("invalid database growth inputs")
    delta = current_bytes - previous_bytes
    return {"current_bytes": current_bytes, "previous_bytes": previous_bytes, "delta_bytes": delta, "daily_delta_bytes": delta / interval_days}


def backup_delete_plan(names: list[str], *, approved: bool, keep: int = 7) -> dict[str, object]:
    if keep < 1:
        raise ValueError("backup keep count must be positive")
    ordered = sorted(set(names), reverse=True)
    return {"keep": ordered[:keep], "delete": ordered[keep:] if approved else [], "blocked": not approved, "dry_run": not approved}
