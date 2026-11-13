from datetime import datetime, timedelta, timezone

import pytest

from src.scan.health import summarize_scan_health
from src.scan.retention import ScanRetentionPolicy, cleanup_plan, duplicate_scan_ids


def test_scan_retention_is_dry_run_by_default():
    now = datetime.now(timezone.utc)
    records = [{"completed_at": (now - timedelta(days=100)).isoformat()}]
    assert cleanup_plan(records, ScanRetentionPolicy(days=90), now=now)["purged"] == 0
    assert ScanRetentionPolicy(days=90, purge_enabled=True, dry_run=False).can_purge()


def test_duplicate_scan_and_health_summary():
    records = [{"scan_id": "a", "image_name": "alpine", "requested_at": "1", "status": "pending"}, {"scan_id": "b", "image_name": "alpine", "requested_at": "1", "status": "running"}]
    assert duplicate_scan_ids(records) == ["b"]
    summary = summarize_scan_health([{"status": "completed"}, {"status": "partial"}])
    assert summary["terminal_rate"] == 1.0 and summary["degraded"]
    with pytest.raises(ValueError): ScanRetentionPolicy(days=0).cutoff()
