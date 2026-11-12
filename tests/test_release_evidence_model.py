from pathlib import Path


def test_release_evidence_migrations_follow_recovery_schema():
    root = Path("src/db/migrations/versions")
    evidence = (root / "20261112_11_release_evidence.py").read_text()
    retry = (root / "20261112_12_recovery_retry_policy.py").read_text()
    assert 'down_revision = "20261112_10"' in evidence
    assert 'revision = "20261112_12"' in retry
    assert "remediation_release_evidence" in evidence
    assert "next_attempt_at" in retry
