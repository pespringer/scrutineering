"""Scan cooldown: how soon an image may be scanned again."""

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
