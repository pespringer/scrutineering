from datetime import datetime, timedelta, timezone

from src.platform.operations_execution import (
    ArchiveExecution,
    BackupExecution,
    ChaosScenario,
    DeploymentObservation,
    LiveSmokePlan,
    ProviderEndToEndFixture,
    RestoreRun,
    TelemetryPoint,
    deployment_reconciliation,
    live_smoke_result,
    production_security_gate,
    recovery_drill_score,
    receiver_independent_execution_manifest,
    telemetry_history,
)


def test_live_smoke_requires_terminal_metrics_and_cleanup():
    plan = LiveSmokePlan("alpine:3.20")
    assert live_smoke_result(plan, status="completed", metrics=True, cleanup=True)["status"] == "passed"
    assert live_smoke_result(plan, status="running", metrics=True, cleanup=True)["status"] == "failed"


def test_backup_and_restore_execution_are_evidence_driven():
    backup = BackupExecution("backup.dump", True, "sha256:abc", True, True, True)
    assert backup.evidence()["ready"] is True
    assert RestoreRun("backup.dump", "isolated", True, True, True, cleaned_up=True).result()["status"] == "passed"


def test_provider_fixture_and_deployment_reconciliation():
    fixture = ProviderEndToEndFixture("github", "org/repo", True, True, True, True)
    assert fixture.result()["status"] == "passed"
    observation = DeploymentObservation(2, "sha256:a", "sha256:a", "completed", 5, 3, 2)
    assert deployment_reconciliation(observation)["decision"] == "verified"


def test_telemetry_history_is_bounded_and_ordered():
    now = datetime.now(timezone.utc)
    points = [TelemetryPoint("scan_latency", value, now + timedelta(seconds=value)) for value in (3, 1, 2)]
    result = telemetry_history(points, metric="scan_latency")
    assert [point["value"] for point in result["points"]] == [1, 2, 3]


def test_archive_plan_and_recovery_score():
    assert ArchiveExecution("tenant-a", (1, 2), batch_size=1, approved=False).plan()["batches"] == 2
    scenarios = [ChaosScenario("redis", True, True, "r1"), ChaosScenario("worker", True, False, "r2")]
    assert recovery_drill_score(scenarios)["status"] == "failed"


def test_security_gate_fails_closed():
    assert production_security_gate(image_digests=True, secrets_restricted=True, drift_clean=True, quota_valid=True, accessibility_checked=True, api_contract_valid=True)["status"] == "ready"
    assert production_security_gate(image_digests=False, secrets_restricted=True, drift_clean=True, quota_valid=True, accessibility_checked=True, api_contract_valid=True)["status"] == "blocked"


def test_manifest_has_100_receiver_independent_execution_slices():
    manifest = receiver_independent_execution_manifest()
    assert len(manifest) == 100
    assert manifest[0]["slice"] == 301 and manifest[-1]["slice"] == 400
    assert all(item["receiver_required"] is False for item in manifest)

