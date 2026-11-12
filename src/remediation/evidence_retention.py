"""Retention policy helpers for release and alert evidence."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone


def retention_days() -> int:
    return min(max(int(os.environ.get("REMEDIATION_EVIDENCE_RETENTION_DAYS", "365")), 7), 3650)


def retention_cutoff(*, now: datetime | None = None) -> datetime:
    current = now or datetime.now(timezone.utc)
    return current.replace(tzinfo=None) - timedelta(days=retention_days())


def purge_enabled() -> bool:
    return os.environ.get("REMEDIATION_EVIDENCE_PURGE_ENABLED", "false").lower() == "true"
