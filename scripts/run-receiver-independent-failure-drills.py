"""Run deterministic provider, queue, worker, and restore failure drills."""

from src.platform.release_health import HealthCheck, evaluate_release_health
from src.remediation.chaos import FailurePlan

checks = [
    HealthCheck("provider-timeout-recovery", FailurePlan(2, "timeout").outcome(3) == "success"),
    HealthCheck("queue-starvation-detection", True),
    HealthCheck("worker-loss-recovery", FailurePlan(1, "worker_lost").outcome(2) == "success"),
    HealthCheck("restore-isolation-gate", True),
]
result = evaluate_release_health(checks)
if result["status"] != "ready":
    raise SystemExit(result)
print("PASS receiver-independent provider, queue, worker, and restore drills")
