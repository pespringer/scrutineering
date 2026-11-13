"""Execution-oriented, receiver-independent contracts for slices 301-400."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from typing import Literal


@dataclass(frozen=True)
class LiveSmokePlan:
    image: str
    timeout_seconds: int = 300
    poll_seconds: int = 3
    require_metrics: bool = True
    require_cleanup: bool = True

    def validate(self) -> "LiveSmokePlan":
        if not self.image or any(char.isspace() for char in self.image):
            raise ValueError("scan image must be a single reference")
        if not 10 <= self.timeout_seconds <= 3600 or not 1 <= self.poll_seconds <= 60:
            raise ValueError("scan polling bounds are invalid")
        return self


def live_smoke_result(plan: LiveSmokePlan, *, status: str, metrics: bool, cleanup: bool, cache_hit: bool = False) -> dict[str, object]:
    plan.validate()
    terminal = status in {"completed", "partial", "failed", "cancelled"}
    checks = {"terminal": terminal, "metrics": metrics or not plan.require_metrics, "cleanup": cleanup or not plan.require_cleanup}
    return {"status": "passed" if status in {"completed", "partial"} and all(checks.values()) else "failed", "checks": checks, "cache_hit": cache_hit, "image": plan.image}


@dataclass(frozen=True)
class BackupExecution:
    name: str
    encrypted: bool
    checksum: str | None
    uploaded: bool
    manifest_persisted: bool
    approved: bool = False

    def evidence(self) -> dict[str, object]:
        blocked = []
        if not self.encrypted:
            blocked.append("encryption_required")
        if not self.checksum or not self.checksum.startswith("sha256:"):
            blocked.append("checksum_required")
        if not self.uploaded:
            blocked.append("upload_incomplete")
        if not self.manifest_persisted:
            blocked.append("manifest_missing")
        if not self.approved:
            blocked.append("approval_required")
        return {"ready": not blocked, "blocked": blocked, "backup": self.name}


@dataclass(frozen=True)
class RestoreRun:
    backup: str
    target: str
    isolated: bool
    migration_check: bool
    checksum_check: bool
    timed_out: bool = False
    cleaned_up: bool = False

    def result(self) -> dict[str, object]:
        checks = {"isolated": self.isolated, "migration": self.migration_check, "checksum": self.checksum_check, "not_timed_out": not self.timed_out, "cleaned_up": self.cleaned_up}
        return {"status": "passed" if all(checks.values()) else "failed", "checks": checks, "backup": self.backup, "target": self.target}


@dataclass(frozen=True)
class ProviderEndToEndFixture:
    provider: Literal["github", "gitlab"]
    repository: str
    authenticated: bool
    branch_protected: bool
    read_ok: bool
    publication_ok: bool
    rate_limited: bool = False

    def result(self) -> dict[str, object]:
        checks = {"authenticated": self.authenticated, "branch_protected": self.branch_protected, "read": self.read_ok, "publication": self.publication_ok, "not_rate_limited": not self.rate_limited}
        return {"status": "passed" if all(checks.values()) else "failed", "provider": self.provider, "repository": self.repository, "checks": checks}


@dataclass(frozen=True)
class DeploymentObservation:
    publication_id: int
    expected_digest: str
    observed_digest: str | None
    scan_status: str
    findings_before: int
    findings_after: int
    poll_attempts: int
    expired: bool = False

    def decision(self) -> str:
        if self.expired:
            return "rollback_required"
        if self.observed_digest != self.expected_digest or self.scan_status != "completed":
            return "rollback_required"
        if self.findings_after > self.findings_before:
            return "rollback_required"
        return "verified"


def deployment_reconciliation(record: DeploymentObservation) -> dict[str, object]:
    if min(record.findings_before, record.findings_after, record.poll_attempts) < 0:
        raise ValueError("deployment observation values cannot be negative")
    return {"publication_id": record.publication_id, "decision": record.decision(), "finding_delta": record.findings_after - record.findings_before, "poll_attempts": record.poll_attempts}


@dataclass(frozen=True)
class BulkExecutionResult:
    action: str
    requested: int
    succeeded: int
    failed: int
    audit_id: str

    def summary(self) -> dict[str, object]:
        if min(self.requested, self.succeeded, self.failed) < 0 or self.succeeded + self.failed > self.requested:
            raise ValueError("bulk result counts are invalid")
        return {"action": self.action, "requested": self.requested, "succeeded": self.succeeded, "failed": self.failed, "partial": self.failed > 0 and self.succeeded > 0, "audit_id": self.audit_id}


@dataclass(frozen=True)
class TelemetryPoint:
    metric: str
    value: float
    recorded_at: datetime
    labels: tuple[tuple[str, str], ...] = ()

    def validate(self) -> "TelemetryPoint":
        if not self.metric or self.value < 0 or self.recorded_at.tzinfo is None:
            raise ValueError("invalid telemetry point")
        return self


def telemetry_history(points: list[TelemetryPoint], *, metric: str, limit: int = 100) -> dict[str, object]:
    if not 1 <= limit <= 1000:
        raise ValueError("telemetry limit is out of bounds")
    selected = [point.validate() for point in points if point.metric == metric]
    selected.sort(key=lambda point: point.recorded_at)
    return {"metric": metric, "points": [{"value": point.value, "recorded_at": point.recorded_at.isoformat(), "labels": dict(point.labels)} for point in selected[-limit:]], "count": min(len(selected), limit)}


@dataclass(frozen=True)
class ArchiveExecution:
    tenant: str | None
    candidate_ids: tuple[int, ...]
    batch_size: int = 1000
    verified_count: int = 0
    approved: bool = False

    def plan(self) -> dict[str, object]:
        if len(self.candidate_ids) > 100000 or not 1 <= self.batch_size <= 10000:
            raise ValueError("archive bounds are invalid")
        if any(candidate_id < 1 for candidate_id in self.candidate_ids):
            raise ValueError("archive IDs must be positive")
        return {"tenant": self.tenant, "candidates": len(self.candidate_ids), "batches": (len(self.candidate_ids) + self.batch_size - 1) // self.batch_size, "verified": self.verified_count, "execute": self.approved}


@dataclass(frozen=True)
class ChaosScenario:
    name: Literal["redis", "postgres", "worker", "provider", "backup", "dashboard"]
    injected: bool
    recovered: bool
    evidence_id: str

    def result(self) -> dict[str, object]:
        return {"scenario": self.name, "passed": self.injected and self.recovered, "evidence_id": self.evidence_id}


def recovery_drill_score(scenarios: list[ChaosScenario]) -> dict[str, object]:
    if not scenarios:
        return {"status": "blocked", "passed": 0, "total": 0}
    results = [scenario.result() for scenario in scenarios]
    passed = sum(bool(result["passed"]) for result in results)
    return {"status": "passed" if passed == len(results) else "failed", "passed": passed, "total": len(results), "results": results}


def production_security_gate(*, image_digests: bool, secrets_restricted: bool, drift_clean: bool, quota_valid: bool, accessibility_checked: bool, api_contract_valid: bool) -> dict[str, object]:
    checks = {"image_digests": image_digests, "secrets_restricted": secrets_restricted, "drift_clean": drift_clean, "quota_valid": quota_valid, "accessibility_checked": accessibility_checked, "api_contract_valid": api_contract_valid}
    return {"status": "ready" if all(checks.values()) else "blocked", "checks": checks, "evidence_key": sha256(repr(sorted(checks.items())).encode()).hexdigest()}


def receiver_independent_execution_manifest() -> list[dict[str, object]]:
    themes = ("live-scan", "backup", "restore", "provider", "publication", "dashboard", "telemetry", "lifecycle", "resilience", "release")
    return [{"slice": number, "theme": themes[(number - 301) // 10], "receiver_required": False} for number in range(301, 401)]

