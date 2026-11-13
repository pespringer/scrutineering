from datetime import datetime, timedelta, timezone

import pytest

from src.platform.production_operations import (
    BackupAutomationPlan,
    BulkWorkflowPlan,
    LifecyclePlan,
    ProviderFixture,
    PublicationReconciliation,
    RestoreExecutionPlan,
    ScanEvidence,
    bulk_workflow_preview,
    lifecycle_preview,
    provider_fixture_readiness,
    receiver_independent_slice_manifest,
    reconciliation_evidence,
    resilience_scorecard,
    restore_execution_status,
    scan_edge_assertions,
    telemetry_dashboard_catalog,
)


def test_live_scan_evidence_and_edge_assertions():
    now = datetime.now(timezone.utc)
    evidence = ScanEvidence("scan-1", "completed", now, now + timedelta(seconds=2), findings=4, cleanup_verified=True)
    result = scan_edge_assertions(evidence)
    assert result["terminal"] is True
    assert result["successful"] is True
    assert result["cleanup_verified"] is True


def test_scan_evidence_rejects_terminal_without_completion():
    with pytest.raises(ValueError):
        ScanEvidence("scan-1", "failed", datetime.now(timezone.utc)).validate()


def test_backup_and_restore_are_fail_closed():
    assert BackupAutomationPlan().validate().encrypted
    plan = RestoreExecutionPlan("backup.dump", "isolated-db", "sha256:abc", True, True, True, True)
    assert restore_execution_status(plan)["ready"] is True
    assert restore_execution_status(plan.__class__(**{**plan.__dict__, "confirmed": False}))["ready"] is False


def test_provider_fixture_requires_permissions_and_protection():
    fixture = ProviderFixture("github", "org/repo", ("repo:read", "pull_request:write"), True, 100)
    assert provider_fixture_readiness(fixture)["ready"] is True
    assert provider_fixture_readiness(ProviderFixture("github", "org/repo", (), False, 0, authenticated=False))["ready"] is False


def test_publication_reconciliation_requires_rollback_plan_when_regressed():
    record = PublicationReconciliation(2, "merged", "sha256:a", "sha256:b", "completed", 2, 3, False)
    result = reconciliation_evidence(record)
    assert result["decision"] == "rollback_required"
    assert result["rollback_ready"] is False


def test_bulk_workflow_requires_confirmation_for_destructive_actions():
    with pytest.raises(ValueError):
        bulk_workflow_preview(BulkWorkflowPlan("archive", (1,), "operator"))
    assert bulk_workflow_preview(BulkWorkflowPlan("retry", (1, 2), "operator"))["count"] == 2


def test_lifecycle_batches_candidates():
    plan = LifecyclePlan(datetime.now(timezone.utc), batch_size=100)
    assert lifecycle_preview(plan, 201)["batches"] == 3


def test_telemetry_catalog_and_scorecard_are_complete():
    assert len(telemetry_dashboard_catalog()) >= 10
    result = resilience_scorecard(queues_healthy=True, backup_fresh=True, workers_healthy=True, provider_ready=True, recovery_drill_passed=False)
    assert result["status"] == "blocked"


def test_manifest_has_exactly_100_receiver_independent_slices():
    manifest = receiver_independent_slice_manifest()
    assert len(manifest) == 100
    assert manifest[0]["slice"] == 201
    assert manifest[-1]["slice"] == 300
    assert all(item["receiver_required"] is False for item in manifest)

