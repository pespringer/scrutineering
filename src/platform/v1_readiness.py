"""Receiver-independent v1.0 readiness contracts for slices 601-700."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Literal


@dataclass(frozen=True)
class ScanPlatformState:
    tenant: str
    queued: int
    active: int
    concurrency_limit: int
    priority_fair: bool
    scanner_healthy: bool
    database_fresh: bool
    replayable: bool

    def result(self) -> dict[str, object]:
        if min(self.queued, self.active, self.concurrency_limit) < 0 or self.active > self.concurrency_limit:
            raise ValueError("scan platform state is invalid")
        checks = {"priority_fair": self.priority_fair, "scanner_healthy": self.scanner_healthy, "database_fresh": self.database_fresh, "replayable": self.replayable}
        return {"tenant": self.tenant, "status": "ready" if all(checks.values()) else "blocked", "checks": checks, "queued": self.queued, "active": self.active}


def scan_replay_key(scan_id: str, scanner_version: str, database_version: str) -> str:
    if not scan_id or not scanner_version or not database_version:
        raise ValueError("scan replay identity is incomplete")
    return sha256(f"{scan_id}:{scanner_version}:{database_version}".encode()).hexdigest()


@dataclass(frozen=True)
class BackupFailoverPlan:
    primary: str
    secondary: str
    primary_healthy: bool
    secondary_healthy: bool
    key_rotation_current: bool
    approved: bool = False

    def result(self) -> dict[str, object]:
        checks = {"primary": self.primary_healthy, "secondary": self.secondary_healthy, "key_rotation": self.key_rotation_current, "distinct_destinations": self.primary != self.secondary}
        return {"status": "ready" if all(checks.values()) and self.approved else "blocked", "checks": checks, "execute": self.approved and all(checks.values())}


@dataclass(frozen=True)
class RestoreLifecycle:
    request_id: str
    state: Literal["requested", "running", "verified", "failed", "cancelled"]
    progress: int
    records_expected: int
    records_restored: int

    def result(self) -> dict[str, object]:
        if not 0 <= self.progress <= 100 or min(self.records_expected, self.records_restored) < 0:
            raise ValueError("restore lifecycle values are invalid")
        checks = {"progress_valid": 0 <= self.progress <= 100, "records_match": self.records_expected == self.records_restored}
        return {"request_id": self.request_id, "state": self.state, "checks": checks, "ready": self.state == "verified" and all(checks.values())}


@dataclass(frozen=True)
class ProviderLifecycle:
    provider: Literal["github", "gitlab"]
    credential_days: int
    permissions_current: bool
    allowlist_current: bool
    branch_policy_current: bool
    replay_protected: bool

    def result(self) -> dict[str, object]:
        if self.credential_days < 0:
            raise ValueError("credential age cannot be negative")
        checks = {"credential": self.credential_days > 7, "permissions": self.permissions_current, "allowlist": self.allowlist_current, "branch_policy": self.branch_policy_current, "replay_protected": self.replay_protected}
        return {"provider": self.provider, "status": "ready" if all(checks.values()) else "blocked", "checks": checks}


@dataclass(frozen=True)
class DashboardView:
    name: str
    actor: str
    filters: tuple[tuple[str, str], ...]
    export_format: Literal["json", "csv", "jsonl"]
    row_limit: int = 1000

    def result(self) -> dict[str, object]:
        if not self.name or not self.actor or not 1 <= self.row_limit <= 100000:
            raise ValueError("dashboard view is invalid")
        return {"name": self.name, "actor": self.actor, "filters": dict(self.filters), "format": self.export_format, "row_limit": self.row_limit}


def telemetry_query(metric: str, start: str, end: str, percentile: str | None = None) -> dict[str, object]:
    if not metric or not start or not end or percentile not in {None, "p50", "p95", "p99"}:
        raise ValueError("telemetry query is invalid")
    return {"metric": metric, "start": start, "end": end, "percentile": percentile, "bounded": True}


@dataclass(frozen=True)
class DatabaseForecast:
    current_gb: float
    daily_growth_gb: float
    retention_days: int
    orphaned_records: int
    duplicate_images: int
    pool_saturation: float

    def result(self) -> dict[str, object]:
        if min(self.current_gb, self.daily_growth_gb, self.retention_days, self.orphaned_records, self.duplicate_images) < 0 or not 0 <= self.pool_saturation <= 1:
            raise ValueError("database forecast values are invalid")
        projected = self.current_gb + self.daily_growth_gb * self.retention_days
        return {"projected_gb": projected, "quality": "healthy" if self.orphaned_records == 0 and self.duplicate_images == 0 and self.pool_saturation < 0.9 else "review_required", "pool_saturation": self.pool_saturation}


@dataclass(frozen=True)
class ScalingDecision:
    queue_depth: int
    workers: int
    utilization: float
    tenant_wait_seconds: float
    starvation: bool

    def result(self) -> dict[str, object]:
        if min(self.queue_depth, self.workers) < 0 or not 0 <= self.utilization <= 1 or self.tenant_wait_seconds < 0:
            raise ValueError("scaling observation is invalid")
        recommendation = "scale_out" if self.starvation or self.queue_depth > max(10, self.workers * 20) or self.utilization > 0.85 else "steady"
        return {"recommendation": recommendation, "queue_depth": self.queue_depth, "workers": self.workers, "tenant_wait_seconds": self.tenant_wait_seconds}


def identity_security_gate(*, service_keys_current: bool, api_keys_expiring: bool, tenants_isolated: bool, roles_current: bool, audit_valid: bool, redaction_valid: bool, container_restricted: bool) -> dict[str, object]:
    checks = {"service_keys": service_keys_current, "api_keys": not api_keys_expiring, "tenants": tenants_isolated, "roles": roles_current, "audit": audit_valid, "redaction": redaction_valid, "containers": container_restricted}
    return {"status": "ready" if all(checks.values()) else "blocked", "checks": checks, "passed": sum(checks.values()), "total": len(checks)}


def documentation_inventory(required: list[str], missing: list[str], stale: list[str]) -> dict[str, object]:
    if not required or any(not path for path in required + missing + stale):
        raise ValueError("documentation inventory is invalid")
    return {"status": "ready" if not missing and not stale else "blocked", "required": len(required), "missing": missing, "stale": stale}


def v1_promotion_gate(*, api_latency_passed: bool, scan_benchmark_passed: bool, backup_benchmark_passed: bool, restore_benchmark_passed: bool, provider_benchmark_passed: bool, migration_passed: bool, load_test_passed: bool, evidence_package_ready: bool) -> dict[str, object]:
    checks = {"api_latency": api_latency_passed, "scan": scan_benchmark_passed, "backup": backup_benchmark_passed, "restore": restore_benchmark_passed, "provider": provider_benchmark_passed, "migration": migration_passed, "load_test": load_test_passed, "evidence_package": evidence_package_ready}
    return {"status": "ready" if all(checks.values()) else "blocked", "checks": checks, "promotion": all(checks.values())}


def receiver_independent_v1_manifest() -> list[dict[str, object]]:
    themes = ("scan", "backup", "restore", "provider", "dashboard", "telemetry", "database", "scaling", "security", "release")
    return [{"slice": number, "theme": themes[(number - 601) // 10], "receiver_required": False} for number in range(601, 701)]

