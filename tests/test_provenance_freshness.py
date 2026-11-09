from datetime import datetime, timezone

from src.scan.provenance import ScannerProvenance, validate_database_freshness


def test_database_freshness_gate():
    records = [ScannerProvenance("trivy", "1", "2026-11-09T00:00:00Z")]
    now = datetime(2026, 11, 9, 12, tzinfo=timezone.utc)
    assert validate_database_freshness(records, 1, now)
    assert not validate_database_freshness(records, 0, now)


def test_database_freshness_requires_parseable_versions():
    assert not validate_database_freshness([ScannerProvenance("trivy", "1")], 1)
