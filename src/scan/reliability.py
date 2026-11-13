"""Deterministic scan scheduling and failure-classification contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


@dataclass(frozen=True)
class ScanCooldown:
    seconds: int = 3600

    def validate(self) -> "ScanCooldown":
        if self.seconds < 0:
            raise ValueError("scan cooldown must not be negative")
        return self


def cooldown_active(last_scan_at: datetime | None, *, policy: ScanCooldown, now: datetime | None = None) -> bool:
    policy.validate()
    if last_scan_at is None:
        return False
    current = now or datetime.now(timezone.utc)
    observed = last_scan_at.replace(tzinfo=timezone.utc) if last_scan_at.tzinfo is None else last_scan_at
    return observed > current - timedelta(seconds=policy.seconds)


def active_scan_image_ids(records: list[object]) -> set[int]:
    """Return image ids with pending/running scans for duplicate suppression."""
    return {
        int(record.image_id)
        for record in records
        if getattr(getattr(record, "status", None), "value", getattr(record, "status", None)) in {"pending", "running"}
    }


def classify_scan_failure(error: BaseException | str, *, timed_out: bool = False) -> str:
    text = str(error).lower()
    if timed_out or "timeout" in text or "timed out" in text:
        return "timeout"
    if "unauthorized" in text or "authentication" in text or "permission" in text:
        return "registry_auth"
    if "rate limit" in text or "too many requests" in text:
        return "registry_rate_limited"
    if "not found" in text or "manifest unknown" in text:
        return "image_not_found"
    if "database" in text or "vulnerability db" in text:
        return "scanner_database"
    return "scanner_failed"


def stale_running_scan(started_at: datetime, *, timeout_seconds: int, now: datetime | None = None) -> bool:
    if timeout_seconds < 1:
        raise ValueError("scan timeout must be positive")
    current = now or datetime.now(timezone.utc)
    observed = started_at.replace(tzinfo=timezone.utc) if started_at.tzinfo is None else started_at
    return observed < current - timedelta(seconds=timeout_seconds)
