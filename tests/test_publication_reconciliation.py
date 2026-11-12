from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from src.remediation.reconciliation import publication_age_seconds, publication_is_stale


def test_verified_merge_is_not_stale_even_when_old():
    now = datetime(2026, 11, 11, 12, 0, tzinfo=timezone.utc)
    record = SimpleNamespace(status="merged", verification_status="verified", completed_at=now - timedelta(days=2), merged_at=now - timedelta(days=2), created_at=now - timedelta(days=2))
    assert publication_age_seconds(record, now=now) == 172800
    assert not publication_is_stale(record, stale_after_seconds=900, now=now)


def test_old_unverified_publication_is_stale():
    now = datetime(2026, 11, 11, 12, 0, tzinfo=timezone.utc)
    record = SimpleNamespace(status="merged", verification_status="rollback_required", completed_at=now - timedelta(minutes=30), merged_at=now - timedelta(minutes=30), created_at=now - timedelta(minutes=30))
    assert publication_is_stale(record, stale_after_seconds=900, now=now)
