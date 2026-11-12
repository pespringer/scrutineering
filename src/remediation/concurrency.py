"""Pure lease/concurrency decisions shared by workers and tests."""

from datetime import datetime


def lease_available(lease_until: datetime | None, now: datetime) -> bool:
    return lease_until is None or lease_until <= now


def next_version(current: int | None) -> int:
    return (current or 0) + 1
