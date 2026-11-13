from datetime import datetime, timedelta, timezone

from src.platform.production_workflows import (
    BackupSchedule,
    DashboardWorkflow,
    DeploymentPoll,
    LifecycleExecution,
    LiveScanEvidenceBundle,
    ProviderConformance,
    RecoveryScenario,
    RestoreVerification,
    TrendPoint,
    backup_schedule_readiness,
    build_scan_evidence,
    post_merge_evidence,
    receiver_independent_workflow_manifest,
    recovery_time_report,
    release_security_evidence,
    trend_series,
)


def test_scan_evidence_requires_failure_context():
    bundle = LiveScanEvidenceBundle("s1", "alpine:3.20", "completed", True, True, False)
    assert build_scan_evidence(bundle)["status"] == "passed"
    assert build_scan_evidence(LiveScanEvidenceBundle("s2", "alpine:3.20", "failed", True, True, False, "timeout"))["status"] == "review_required"


def test_backup_and_restore_workflows():
    assert backup_schedule_readiness(BackupSchedule("nightly", "daily", "s3://backups", True, True))["ready"] is True
    assert RestoreVerification("isolated", 3, 3, "a", "a", True).result()["status"] == "passed"


def test_provider_and_post_merge_contracts():
    provider = ProviderConformance("github", True, True, True, True, True, True)
    assert provider.report()["status"] == "passed"
    assert post_merge_evidence(DeploymentPoll(1, 2, "sha256:a", "sha256:a", "completed", -2))["decision"] == "verified"


def test_dashboard_and_trend_workflows_are_bounded():
    assert DashboardWorkflow("bulk", "operator", 2, True).preview()["execute"] is False
    now = datetime.now(timezone.utc)
    points = [TrendPoint("latency", value, now + timedelta(seconds=value)) for value in (2, 1)]
    assert trend_series(points, "latency")["count"] == 2


def test_lifecycle_recovery_and_release_evidence():
    assert LifecycleExecution("tenant-a", (1, 2), 1, False, (1,)).result()["verified"] == 1
    scenarios = [RecoveryScenario("redis", True, True, 2), RecoveryScenario("worker", True, True, 3)]
    assert recovery_time_report(scenarios, 5)["status"] == "passed"
    assert release_security_evidence(digests=True, secrets=True, drift=True, quota=True, accessibility=True, contracts=True, runbooks=True)["status"] == "ready"


def test_workflow_manifest_is_exactly_100_receiver_independent_slices():
    manifest = receiver_independent_workflow_manifest()
    assert len(manifest) == 100
    assert manifest[0]["slice"] == 401 and manifest[-1]["slice"] == 500
    assert all(item["receiver_required"] is False for item in manifest)

