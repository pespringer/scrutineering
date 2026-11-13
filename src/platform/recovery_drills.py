"""Deterministic recovery rehearsal contracts."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DrillResult:
    name: str
    passed: bool
    detail: str


def simulate_failover(name: str, *, primary_healthy: bool, replica_ready: bool) -> DrillResult:
    if not name:
        raise ValueError("drill name is required")
    passed = (not primary_healthy) and replica_ready
    return DrillResult(name, passed, "replica promotion path available" if passed else "failover prerequisites not met")


def simulate_worker_loss(*, queued: int, replacement_ready: bool) -> DrillResult:
    passed = queued >= 0 and replacement_ready
    return DrillResult("worker-loss", passed, "replacement worker can drain queue" if passed else "queue recovery blocked")


def recovery_score(results: list[DrillResult]) -> dict[str, object]:
    return {"passed": sum(item.passed for item in results), "failed": sum(not item.passed for item in results), "ready": bool(results) and all(item.passed for item in results)}
