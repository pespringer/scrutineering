"""Receiver-independent release and service health evaluation."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class HealthCheck:
    name: str
    passed: bool
    detail: str = ""
    required: bool = True


def evaluate_release_health(checks: list[HealthCheck]) -> dict[str, object]:
    if not checks:
        return {"status": "blocked", "passed": 0, "failed": 0, "checks": [], "blocking": ["no_checks"]}
    blocking = [check.name for check in checks if check.required and not check.passed]
    return {
        "status": "ready" if not blocking else "blocked",
        "passed": sum(check.passed for check in checks),
        "failed": sum(not check.passed for check in checks),
        "checks": [{"name": check.name, "passed": check.passed, "detail": check.detail, "required": check.required} for check in checks],
        "blocking": blocking,
    }


def evaluate_slo(*, name: str, observed: float, target: float, lower_is_better: bool = True) -> dict[str, object]:
    if observed < 0 or target < 0:
        raise ValueError("SLO values must not be negative")
    passed = observed <= target if lower_is_better else observed >= target
    return {"name": name, "observed": observed, "target": target, "passed": passed}
