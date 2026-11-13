"""Run deterministic scale, failover, and deployment maturity checks."""

from src.platform.deployment_controls import rollout_health, validate_container_security, validate_image_pin, validate_resources
from src.platform.recovery_drills import recovery_score, simulate_failover, simulate_worker_loss
from src.platform.scale_controls import autoscale_recommendation, queue_recovery, tenant_queue_quota

checks = [
    validate_image_pin("scrutineering/api@sha256:" + "a" * 64),
    validate_container_security(run_as_non_root=True, read_only_root=True, privilege_escalation=False),
    validate_resources(250, 512),
]
recovery = recovery_score([simulate_failover("postgres", primary_healthy=False, replica_ready=True), simulate_failover("redis", primary_healthy=False, replica_ready=True), simulate_worker_loss(queued=2, replacement_ready=True)])
assert all(check.passed for check in checks)
assert recovery["ready"]
assert rollout_health(desired=2, ready=2)["ready"]
assert tenant_queue_quota("platform", 1, 2)["admit"]
assert autoscale_recommendation(queue_depth=25, workers=1)["desired_workers"] == 3
assert queue_recovery(depth=1, oldest_age_seconds=901)["starved"]
print("PASS platform maturity, failover, scaling, and deployment drill")
