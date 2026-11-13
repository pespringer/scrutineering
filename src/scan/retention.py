"""Dry-run-first scan lifecycle and cleanup planning."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


@dataclass(frozen=True)
class ScanRetentionPolicy:
    days: int = 90
    purge_enabled: bool = False
    dry_run: bool = True

    def cutoff(self, now: datetime | None = None) -> datetime:
        if self.days < 1:
            raise ValueError("scan retention days must be positive")
        return (now or datetime.now(timezone.utc)) - timedelta(days=self.days)

    def can_purge(self) -> bool:
        return self.purge_enabled and not self.dry_run


def duplicate_scan_ids(records: list[dict], *, window_seconds: int = 3600) -> list[str]:
    """Return pending/running duplicate IDs, preserving the first request."""
    if window_seconds < 1:
        raise ValueError("duplicate window must be positive")
    seen: set[str] = set()
    duplicates: list[str] = []
    for record in records:
        key = f"{record.get('image_name')}:{record.get('requested_at')}"
        scan_id = str(record.get("scan_id", ""))
        if record.get("status") in {"pending", "running"} and key in seen:
            duplicates.append(scan_id)
        seen.add(key)
    return duplicates


def cleanup_plan(records: list[dict], policy: ScanRetentionPolicy, *, now: datetime | None = None) -> dict[str, object]:
    cutoff = policy.cutoff(now)
    eligible = [record for record in records if record.get("completed_at") and record["completed_at"] < cutoff.isoformat()]
    return {"cutoff": cutoff.isoformat(), "eligible": len(eligible), "purge_enabled": policy.purge_enabled, "dry_run": policy.dry_run, "purged": len(eligible) if policy.can_purge() else 0}
