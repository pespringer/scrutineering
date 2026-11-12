"""Exercise stale publication classification with deterministic records."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from src.remediation.reconciliation import publication_age_seconds, publication_is_stale


def main() -> None:
    now = datetime(2026, 11, 11, 12, 0, tzinfo=timezone.utc)
    old = now - timedelta(minutes=20)
    pending = SimpleNamespace(status="pending", verification_status=None, completed_at=None, merged_at=None, created_at=old)
    verified = SimpleNamespace(status="merged", verification_status="verified", completed_at=old, merged_at=old, created_at=old)
    recent = SimpleNamespace(status="failed", verification_status=None, completed_at=now - timedelta(seconds=10), merged_at=None, created_at=old)
    assert publication_age_seconds(pending, now=now) == 1200
    assert publication_is_stale(pending, stale_after_seconds=900, now=now)
    assert not publication_is_stale(verified, stale_after_seconds=900, now=now)
    assert not publication_is_stale(recent, stale_after_seconds=900, now=now)
    print("PASS stale publication classification")


if __name__ == "__main__":
    main()
