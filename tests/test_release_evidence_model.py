from pathlib import Path

from src.remediation.evidence_retention import retention_cutoff, retention_days


def test_release_evidence_migrations_follow_recovery_schema():
    root = Path("src/db/migrations/versions")
    evidence = (root / "20261112_11_release_evidence.py").read_text()
    retry = (root / "20261112_12_recovery_retry_policy.py").read_text()
    alert = (root / "20261112_13_alert_evidence.py").read_text()
    queue = (root / "20261112_14_delivery_queue_and_leases.py").read_text()
    assert 'down_revision = "20261112_10"' in evidence
    assert 'revision = "20261112_12"' in retry
    assert "remediation_release_evidence" in evidence
    assert "next_attempt_at" in retry
    assert 'down_revision = "20261112_12"' in alert
    assert "remediation_alert_evidence" in alert
    assert 'down_revision = "20261112_13"' in queue
    assert "remediation_alert_deliveries" in queue


def test_evidence_retention_is_bounded(monkeypatch):
    monkeypatch.setenv("REMEDIATION_EVIDENCE_RETENTION_DAYS", "1")
    assert retention_days() == 7
    monkeypatch.setenv("REMEDIATION_EVIDENCE_RETENTION_DAYS", "99999")
    assert retention_days() == 3650
    assert retention_cutoff().tzinfo is None
