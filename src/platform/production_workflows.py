"""Receiver-independent production workflow contracts for slices 401-500."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from typing import Literal


@dataclass(frozen=True)
class LiveScanEvidenceBundle:
    scan_id: str
    image: str
    status: Literal["completed", "partial", "failed", "cancelled"]
    metrics_reachable: bool
    cleanup_verified: bool
    cache_hit: bool
    failure_category: str | None = None
    staging: bool = False

    def validate(self) -> "LiveScanEvidenceBundle":
        if not self.scan_id or not self.image or any(char.isspace() for char in self.image):
            raise ValueError("scan evidence identity is invalid")
        if self.status in {"failed", "cancelled"} and not self.failure_category:
            raise ValueError("failed scans require a failure category")
        return self


def build_scan_evidence(bundle: LiveScanEvidenceBundle) -> dict[str, object]:
    bundle.validate()
    passed = bundle.status in {"completed", "partial"} and bundle.metrics_reachable and bundle.cleanup_verified
    return {"status": "passed" if passed else "review_required", "scan_id": bundle.scan_id, "image": bundle.image, "cache_hit": bundle.cache_hit, "failure_category": bundle.failure_category, "staging": bundle.staging, "digest": sha256(f"{bundle.scan_id}:{bundle.status}:{bundle.image}".encode()).hexdigest()}


@dataclass(frozen=True)
class BackupSchedule:
    name: str
    interval: Literal["hourly", "daily", "weekly"]
    destination: str
    encrypted: bool
    approved: bool = False

    def validate(self) -> "BackupSchedule":
        if not self.name or not self.destination or not self.encrypted:
            raise ValueError("backup schedule requires an encrypted destination")
        return self


def backup_schedule_readiness(schedule: BackupSchedule) -> dict[str, object]:
    schedule.validate()
    return {"ready": schedule.approved, "approved": schedule.approved, "interval": schedule.interval, "destination": schedule.destination}


@dataclass(frozen=True)
class RestoreVerification:
    target: str
    expected_records: int
    actual_records: int
    expected_checksum: str
    actual_checksum: str
    cleaned_up: bool

    def result(self) -> dict[str, object]:
        if min(self.expected_records, self.actual_records) < 0:
            raise ValueError("restore record counts cannot be negative")
        checks = {"record_count": self.expected_records == self.actual_records, "checksum": self.expected_checksum == self.actual_checksum, "cleanup": self.cleaned_up}
        return {"status": "passed" if all(checks.values()) else "failed", "target": self.target, "checks": checks}


@dataclass(frozen=True)
class ProviderConformance:
    provider: Literal["github", "gitlab"]
    read: bool
    pagination: bool
    permissions: bool
    branch_protection: bool
    rate_limit_recovery: bool
    timeout_recovery: bool

    def report(self) -> dict[str, object]:
        checks = {"read": self.read, "pagination": self.pagination, "permissions": self.permissions, "branch_protection": self.branch_protection, "rate_limit_recovery": self.rate_limit_recovery, "timeout_recovery": self.timeout_recovery}
        return {"provider": self.provider, "status": "passed" if all(checks.values()) else "failed", "checks": checks}


@dataclass(frozen=True)
class DeploymentPoll:
    publication_id: int
    attempt: int
    expected_digest: str
    observed_digest: str | None
    scan_status: str
    findings_delta: int
    expired: bool = False

    def decision(self) -> str:
        if self.expired or self.observed_digest != self.expected_digest or self.scan_status != "completed" or self.findings_delta > 0:
            return "rollback_required"
        return "verified"


def post_merge_evidence(poll: DeploymentPoll) -> dict[str, object]:
    if poll.publication_id < 1 or poll.attempt < 1:
        raise ValueError("deployment poll identity is invalid")
    return {"publication_id": poll.publication_id, "attempt": poll.attempt, "decision": poll.decision(), "finding_delta": poll.findings_delta}


@dataclass(frozen=True)
class DashboardWorkflow:
    action: Literal["filter", "sort", "poll", "bulk", "export"]
    actor: str
    target_count: int
    confirmed: bool = False

    def preview(self) -> dict[str, object]:
        if not self.actor or not 0 <= self.target_count <= 100:
            raise ValueError("dashboard workflow bounds are invalid")
        if self.action == "bulk" and self.target_count and not self.confirmed:
            raise ValueError("bulk workflow requires confirmation")
        return {"action": self.action, "actor": self.actor, "target_count": self.target_count, "execute": False}


@dataclass(frozen=True)
class TrendPoint:
    metric: str
    value: float
    recorded_at: datetime


def trend_series(points: list[TrendPoint], metric: str, limit: int = 100) -> dict[str, object]:
    if not metric or not 1 <= limit <= 1000:
        raise ValueError("trend query is invalid")
    selected = sorted((point for point in points if point.metric == metric), key=lambda point: point.recorded_at)[-limit:]
    return {"metric": metric, "count": len(selected), "points": [{"value": point.value, "recorded_at": point.recorded_at.isoformat()} for point in selected]}


@dataclass(frozen=True)
class LifecycleExecution:
    tenant: str | None
    candidate_ids: tuple[int, ...]
    batch_size: int
    approved: bool
    verified_ids: tuple[int, ...] = ()

    def result(self) -> dict[str, object]:
        if not 1 <= self.batch_size <= 10000 or any(item < 1 for item in self.candidate_ids):
            raise ValueError("lifecycle execution bounds are invalid")
        verified = set(self.verified_ids)
        return {"tenant": self.tenant, "candidates": len(self.candidate_ids), "batches": (len(self.candidate_ids) + self.batch_size - 1) // self.batch_size, "approved": self.approved, "verified": len(verified.intersection(self.candidate_ids)), "execute": self.approved}


@dataclass(frozen=True)
class RecoveryScenario:
    service: Literal["redis", "postgres", "worker", "provider", "backup", "dashboard"]
    injected: bool
    recovered: bool
    recovery_seconds: float

    def result(self) -> dict[str, object]:
        if self.recovery_seconds < 0:
            raise ValueError("recovery duration cannot be negative")
        return {"service": self.service, "passed": self.injected and self.recovered, "recovery_seconds": self.recovery_seconds}


def recovery_time_report(scenarios: list[RecoveryScenario], target_seconds: float = 300) -> dict[str, object]:
    if target_seconds <= 0:
        raise ValueError("recovery target must be positive")
    results = [scenario.result() for scenario in scenarios]
    passed = sum(bool(item["passed"]) and item["recovery_seconds"] <= target_seconds for item in results)
    return {"status": "passed" if results and passed == len(results) else "failed", "passed": passed, "total": len(results), "results": results}


def release_security_evidence(*, digests: bool, secrets: bool, drift: bool, quota: bool, accessibility: bool, contracts: bool, runbooks: bool) -> dict[str, object]:
    checks = {"digests": digests, "secrets": secrets, "drift": drift, "quota": quota, "accessibility": accessibility, "contracts": contracts, "runbooks": runbooks}
    return {"status": "ready" if all(checks.values()) else "blocked", "checks": checks, "evidence_key": sha256(repr(sorted(checks.items())).encode()).hexdigest()}


def receiver_independent_workflow_manifest() -> list[dict[str, object]]:
    themes = ("scan", "backup", "restore", "provider", "publication", "dashboard", "telemetry", "lifecycle", "resilience", "release")
    return [{"slice": number, "theme": themes[(number - 401) // 10], "receiver_required": False} for number in range(401, 501)]

