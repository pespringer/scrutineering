from datetime import datetime, timedelta, timezone

import pytest

from src.platform.backup_lifecycle import BackupArtifact, backup_fresh, restore_preflight, rotation_plan
from src.platform.operations import BackupRotation
from src.scan.reliability import ScanCooldown, classify_scan_failure, cooldown_active, stale_running_scan
from src.scan.registry_diagnostics import classify_registry_error, diagnose_registry, private_registry_evidence
from src.platform import backup_tasks
from src.platform.backup_tasks import _pg_dump_database_url, report_backup_freshness
from src.platform.onboarding import onboarding_summary


def test_backup_rotation_is_dry_run_and_freshness_is_bounded():
    now = datetime(2026, 11, 12, tzinfo=timezone.utc)
    artifacts = [BackupArtifact("003.dump", now, 10), BackupArtifact("002.dump", now - timedelta(days=2), 10), BackupArtifact("001.dump", now - timedelta(days=4), 10)]
    assert rotation_plan(artifacts, BackupRotation(keep=2))["remove"] == ["001.dump"]
    assert backup_fresh(artifacts[0], max_age_days=1, now=now)
    assert not backup_fresh(artifacts[2], max_age_days=1, now=now)


def test_restore_preflight_fails_closed_without_isolation_and_confirmation():
    assert not restore_preflight(manifest_valid=True, target_is_isolated=False, confirmation=True)["ready"]
    assert restore_preflight(manifest_valid=True, target_is_isolated=True, confirmation=True)["ready"]


def test_scan_reliability_contracts_classify_and_suppress():
    now = datetime(2026, 11, 12, tzinfo=timezone.utc)
    assert cooldown_active(now - timedelta(minutes=5), policy=ScanCooldown(3600), now=now)
    assert not cooldown_active(now - timedelta(hours=2), policy=ScanCooldown(3600), now=now)
    assert stale_running_scan(now - timedelta(hours=1), timeout_seconds=60, now=now)
    assert classify_scan_failure("manifest unknown") == "image_not_found"
    with pytest.raises(ValueError): ScanCooldown(-1).validate()


def test_registry_diagnostics_never_expose_secret_values():
    result = diagnose_registry("ghcr.io", {"GITHUB_TOKEN": "secret"})
    assert result.configured and result.missing_keys == ()
    assert "secret" not in result.message
    assert classify_registry_error("429 too many requests") == "rate_limited"
    evidence = private_registry_evidence(registry="ghcr.io", digest="sha256:" + "a" * 64, authenticated=True, credential_keys=("GITHUB_TOKEN",))
    assert evidence["credentials_redacted"] is True


def test_backup_task_is_explicitly_not_configured_without_metadata():
    assert report_backup_freshness(metadata_path="", dry_run=True)["status"] == "not_configured"


def test_pg_dump_url_removes_sqlalchemy_driver_suffix():
    assert _pg_dump_database_url("postgresql+psycopg2://user:secret@postgres:5432/db") == "postgresql://user:secret@postgres:5432/db"


def test_onboarding_summary_separates_required_and_deferred_steps():
    result = onboarding_summary([
        {"key": "database", "status": "ready"},
        {"key": "source", "status": "action"},
        {"key": "alerts", "status": "deferred"},
    ])
    assert result["status"] == "action_required"
    assert result["completed"] == 1
    assert result["required"] == 2
    assert result["actions"] == ["source"]


def test_backup_observation_is_persisted_once_with_audit_evidence(monkeypatch):
    class FakeQuery:
        def filter_by(self, **_filters):
            return self

        def one_or_none(self):
            return None

    class FakeSession:
        def __init__(self):
            self.added = []

        def query(self, _model):
            return FakeQuery()

        def add(self, value):
            self.added.append(value)

        def flush(self):
            for value in self.added:
                if value.__class__.__name__ == "BackupExecution":
                    value.id = 41

    session = FakeSession()

    class SessionContext:
        def __enter__(self):
            return session

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(backup_tasks, "get_session", lambda: SessionContext())
    backup_tasks._record_artifact_observation(
        BackupArtifact("verified.dump", datetime.now(timezone.utc), 512, verified=True),
        source="test",
    )

    assert any(item.__class__.__name__ == "BackupExecution" and item.verified for item in session.added)
    assert any(item.__class__.__name__ == "AuditLog" for item in session.added)
