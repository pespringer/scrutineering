from datetime import datetime, timedelta, timezone

import pytest

from src.db.lifecycle import ArchivePolicy, archive_candidates, backup_delete_plan, growth_report, tenant_retention
from src.platform.deployment_controls import configuration_drift, rollout_health, validate_container_security, validate_image_pin, validate_resources
from src.platform.recovery_drills import recovery_score, simulate_failover, simulate_worker_loss
from src.platform.scale_controls import autoscale_recommendation, queue_recovery, tenant_queue_quota
from src.platform.promotion_gate import production_promotion_gate
from src.remediation.execution_resilience import ExecutionLease, ExecutionResourceBudget, RetryBudget, replay_allowed, tenant_execution_capacity
from src.remediation.provider_hardening import ProviderRequestBudget, circuit_state, redact_provider_payload


def test_execution_resilience_is_lease_and_budget_bounded():
    now = datetime(2026, 11, 12, tzinfo=timezone.utc)
    lease = ExecutionLease("worker-1", 1, now + timedelta(minutes=5))
    renewed = lease.renew("worker-1", now=now)
    assert renewed.version == 2 and renewed.active(now=now)
    assert RetryBudget(2).consume().used_attempts == 1
    assert ExecutionResourceBudget().validate()
    assert replay_allowed(state="approved", approved=True, lease_active=True, artifact_fingerprint="abc")
    assert tenant_execution_capacity(2, 3)["admit"]
    with pytest.raises(ValueError): lease.renew("other", now=now)


def test_deployment_controls_fail_closed_on_mutable_or_privileged_config():
    assert validate_image_pin("api@sha256:" + "a" * 64).passed
    assert not validate_image_pin("api:latest").passed
    assert validate_container_security(run_as_non_root=True, read_only_root=True, privilege_escalation=False).passed
    assert not validate_container_security(run_as_non_root=False, read_only_root=True, privilege_escalation=False).passed
    assert validate_resources(100, 256).passed
    assert rollout_health(desired=2, ready=1)["ready"] is False
    assert configuration_drift({"A": "1"}, {"A": "2"})["drift"]


def test_database_lifecycle_is_dry_run_by_default():
    now = datetime(2026, 11, 12, tzinfo=timezone.utc)
    records = [{"id": 1, "created_at": now - timedelta(days=10)}, {"id": 2, "created_at": now}]
    assert [item["id"] for item in archive_candidates(records, timestamp_key="created_at", policy=ArchivePolicy(days=7), now=now)] == [1]
    assert backup_delete_plan(["003", "002", "001"], approved=False)["delete"] == []
    assert growth_report(current_bytes=200, previous_bytes=100, interval_days=2)["daily_delta_bytes"] == 50
    assert tenant_retention("team-a", 30)["purge_enabled"] is False


def test_provider_scale_and_recovery_controls():
    assert redact_provider_payload({"token": "secret", "nested": {"password": "x"}})["token"] == "[REDACTED]"
    assert ProviderRequestBudget(2).admit().used_requests == 1
    assert circuit_state(failures=3, threshold=3, opened=True)["admit"] is False
    assert tenant_queue_quota("team-a", 1, 2)["admit"]
    assert autoscale_recommendation(queue_depth=25, workers=1)["desired_workers"] == 3
    assert queue_recovery(depth=1, oldest_age_seconds=901)["starved"]
    score = recovery_score([simulate_failover("db", primary_healthy=False, replica_ready=True), simulate_worker_loss(queued=1, replacement_ready=True)])
    assert score["ready"]


def test_promotion_gate_requires_every_required_check():
    ready = production_promotion_gate(tests_passed=True, migrations_valid=True, deployment_valid=True, backup_fresh=True, recovery_ready=True, configuration_clean=True)
    blocked = production_promotion_gate(tests_passed=True, migrations_valid=False, deployment_valid=True, backup_fresh=True, recovery_ready=True, configuration_clean=True)
    assert ready["status"] == "ready"
    assert blocked["status"] == "blocked" and "migrations" in blocked["blocking"]
