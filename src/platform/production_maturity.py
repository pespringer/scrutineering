"""Production-maturity contracts for receiver-independent slices 501-600."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from statistics import quantiles
from typing import Literal


@dataclass(frozen=True)
class ScanOrchestration:
    tenant: str
    priority: Literal["low", "normal", "high"]
    concurrency_limit: int
    cooldown_seconds: int
    scanner_version: str
    vulnerability_db_version: str

    def validate(self) -> "ScanOrchestration":
        if not self.tenant or not 1 <= self.concurrency_limit <= 100 or self.cooldown_seconds < 0:
            raise ValueError("scan orchestration limits are invalid")
        if not self.scanner_version or not self.vulnerability_db_version:
            raise ValueError("scanner version evidence is required")
        return self


def scan_orchestration_report(config: ScanOrchestration, *, queued: int, suppressed: int, retried: int) -> dict[str, object]:
    config.validate()
    if min(queued, suppressed, retried) < 0:
        raise ValueError("scan counts cannot be negative")
    return {"tenant": config.tenant, "priority": config.priority, "queued": queued, "suppressed": suppressed, "retried": retried, "concurrency_limit": config.concurrency_limit, "scanner_version": config.scanner_version, "vulnerability_db_version": config.vulnerability_db_version}


def reproducibility_check(*, expected_digest: str, actual_digest: str, expected_findings: int, actual_findings: int) -> dict[str, object]:
    if min(expected_findings, actual_findings) < 0:
        raise ValueError("finding counts cannot be negative")
    return {"reproducible": expected_digest == actual_digest and expected_findings == actual_findings, "digest_match": expected_digest == actual_digest, "findings_match": expected_findings == actual_findings}


@dataclass(frozen=True)
class BackupDestinationHealth:
    destination: str
    reachable: bool
    encrypted: bool
    key_age_days: int
    upload_seconds: float

    def result(self) -> dict[str, object]:
        if self.key_age_days < 0 or self.upload_seconds < 0:
            raise ValueError("backup destination measurements are invalid")
        checks = {"reachable": self.reachable, "encrypted": self.encrypted, "key_rotation_current": self.key_age_days <= 90}
        return {"destination": self.destination, "status": "healthy" if all(checks.values()) else "degraded", "checks": checks, "upload_seconds": self.upload_seconds}


@dataclass(frozen=True)
class RestoreRequest:
    request_id: str
    actor: str
    backup_name: str
    target: str
    approved: bool
    isolated: bool

    def audit(self) -> dict[str, object]:
        return {"request_id": self.request_id, "actor": self.actor, "backup": self.backup_name, "target": self.target, "approved": self.approved, "isolated": self.isolated, "execute": self.approved and self.isolated}


@dataclass(frozen=True)
class ProviderReadiness:
    provider: Literal["github", "gitlab"]
    credential_expires_in_days: int
    permissions_current: bool
    allowlisted: bool
    branch_policy_hash: str

    def result(self) -> dict[str, object]:
        if self.credential_expires_in_days < 0 or not self.branch_policy_hash:
            raise ValueError("provider readiness metadata is invalid")
        checks = {"credential_current": self.credential_expires_in_days > 7, "permissions": self.permissions_current, "allowlisted": self.allowlisted}
        return {"provider": self.provider, "status": "ready" if all(checks.values()) else "blocked", "checks": checks, "branch_policy_hash": self.branch_policy_hash}


def publication_replay_key(provider: str, publication_id: int, request_hash: str) -> str:
    if not provider or publication_id < 1 or not request_hash:
        raise ValueError("publication replay identity is invalid")
    return sha256(f"{provider}:{publication_id}:{request_hash}".encode()).hexdigest()


@dataclass(frozen=True)
class DashboardReport:
    name: str
    actor: str
    filters: tuple[tuple[str, str], ...]
    rows: int
    exportable: bool = True

    def result(self) -> dict[str, object]:
        if not self.name or not self.actor or not 0 <= self.rows <= 100000:
            raise ValueError("dashboard report bounds are invalid")
        return {"name": self.name, "actor": self.actor, "filters": dict(self.filters), "rows": self.rows, "exportable": self.exportable}


def percentile_metrics(values: list[float]) -> dict[str, float]:
    if not values or any(value < 0 for value in values):
        raise ValueError("metric values must be non-negative")
    ordered = sorted(values)
    if len(ordered) == 1:
        return {"p50": ordered[0], "p95": ordered[0], "p99": ordered[0]}
    cuts = quantiles(ordered, n=100, method="inclusive")
    return {"p50": cuts[49], "p95": cuts[94], "p99": cuts[98]}


def failure_rate(total: int, failures: int) -> float:
    if total < 1 or not 0 <= failures <= total:
        raise ValueError("failure counts are invalid")
    return failures / total


@dataclass(frozen=True)
class DatabaseQuality:
    table_count: int
    orphaned_records: int
    duplicate_images: int
    index_recommendations: int
    pool_saturation: float

    def result(self) -> dict[str, object]:
        if min(self.table_count, self.orphaned_records, self.duplicate_images, self.index_recommendations) < 0 or not 0 <= self.pool_saturation <= 1:
            raise ValueError("database quality metrics are invalid")
        return {"status": "healthy" if self.orphaned_records == 0 and self.duplicate_images == 0 and self.pool_saturation < 0.9 else "review_required", "table_count": self.table_count, "orphaned_records": self.orphaned_records, "duplicate_images": self.duplicate_images, "index_recommendations": self.index_recommendations, "pool_saturation": self.pool_saturation}


@dataclass(frozen=True)
class ScalingObservation:
    queue_depth: int
    workers: int
    tenant_wait_seconds: float
    starvation_detected: bool

    def result(self) -> dict[str, object]:
        if min(self.queue_depth, self.workers) < 0 or self.tenant_wait_seconds < 0:
            raise ValueError("scaling observation is invalid")
        recommendation = "scale_out" if self.queue_depth > max(10, self.workers * 20) or self.starvation_detected else "steady"
        return {"recommendation": recommendation, "queue_depth": self.queue_depth, "workers": self.workers, "tenant_wait_seconds": self.tenant_wait_seconds}


def identity_security_score(*, keys_current: bool, tenants_isolated: bool, roles_current: bool, audit_integrity: bool, redaction_verified: bool) -> dict[str, object]:
    checks = {"keys_current": keys_current, "tenants_isolated": tenants_isolated, "roles_current": roles_current, "audit_integrity": audit_integrity, "redaction_verified": redaction_verified}
    return {"status": "ready" if all(checks.values()) else "blocked", "checks": checks, "passed": sum(checks.values()), "total": len(checks)}


def documentation_freshness(*, required_paths: list[str], missing_paths: list[str], stale_paths: list[str]) -> dict[str, object]:
    if any(not path for path in required_paths + missing_paths + stale_paths):
        raise ValueError("documentation paths must not be empty")
    return {"status": "ready" if not missing_paths and not stale_paths else "blocked", "required": len(required_paths), "missing": missing_paths, "stale": stale_paths}


def promotion_gate(*, api_latency: dict[str, float], scan_throughput: float, backup_throughput: float, restore_throughput: float, migration_passed: bool, load_test_passed: bool, evidence_package: bool) -> dict[str, object]:
    if min(scan_throughput, backup_throughput, restore_throughput) < 0:
        raise ValueError("throughput values cannot be negative")
    checks = {"api_latency": all(value >= 0 for value in api_latency.values()), "scan_throughput": scan_throughput > 0, "backup_throughput": backup_throughput > 0, "restore_throughput": restore_throughput > 0, "migration": migration_passed, "load_test": load_test_passed, "evidence_package": evidence_package}
    return {"status": "ready" if all(checks.values()) else "blocked", "checks": checks}


def receiver_independent_maturity_manifest() -> list[dict[str, object]]:
    themes = ("scan", "backup", "restore", "provider", "dashboard", "telemetry", "database", "resilience", "security", "release")
    return [{"slice": number, "theme": themes[(number - 501) // 10], "receiver_required": False} for number in range(501, 601)]

