"""Receiver-independent production operations for slices 201-300.

The module contains deterministic planning and evidence contracts.  Network
calls, destructive database work, and external alert delivery stay behind
explicit adapters and are never performed by these helpers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from typing import Literal


TERMINAL_SCAN_STATES = {"completed", "partial", "failed", "cancelled"}


@dataclass(frozen=True)
class ScanEvidence:
    scan_id: str
    status: str
    started_at: datetime
    completed_at: datetime | None = None
    findings: int = 0
    cache_hit: bool = False
    cancelled: bool = False
    cleanup_verified: bool = False

    def validate(self) -> "ScanEvidence":
        if not self.scan_id or self.status not in {"pending", "running", *TERMINAL_SCAN_STATES}:
            raise ValueError("invalid scan evidence")
        if self.started_at.tzinfo is None or self.findings < 0:
            raise ValueError("scan evidence metadata is invalid")
        if self.completed_at and self.completed_at < self.started_at:
            raise ValueError("scan completion precedes start")
        if self.status in TERMINAL_SCAN_STATES and not self.completed_at:
            raise ValueError("terminal scans require completion time")
        if self.cancelled != (self.status == "cancelled"):
            raise ValueError("cancelled flag does not match scan state")
        return self


def scan_edge_assertions(evidence: ScanEvidence) -> dict[str, object]:
    evidence.validate()
    return {
        "terminal": evidence.status in TERMINAL_SCAN_STATES,
        "successful": evidence.status in {"completed", "partial"},
        "cache_hit": evidence.cache_hit,
        "cleanup_verified": evidence.cleanup_verified,
        "evidence_key": sha256(f"scan:{evidence.scan_id}:{evidence.status}".encode()).hexdigest(),
    }


@dataclass(frozen=True)
class BackupAutomationPlan:
    schedule: str = "daily"
    retention: int = 7
    freshness_hours: int = 30
    encrypted: bool = True
    upload_retries: int = 3
    approved: bool = False

    def validate(self) -> "BackupAutomationPlan":
        if self.schedule not in {"hourly", "daily", "weekly"}:
            raise ValueError("unsupported backup schedule")
        if min(self.retention, self.freshness_hours, self.upload_retries) < 1:
            raise ValueError("backup limits must be positive")
        if not self.encrypted:
            raise ValueError("production backups must be encrypted")
        return self


@dataclass(frozen=True)
class RestoreExecutionPlan:
    backup_name: str
    target: str
    manifest_digest: str
    isolated: bool
    migration_compatible: bool
    checksum_verified: bool
    confirmed: bool = False

    def ready(self) -> bool:
        return bool(
            self.backup_name
            and self.target
            and self.manifest_digest.startswith("sha256:")
            and self.isolated
            and self.migration_compatible
            and self.checksum_verified
            and self.confirmed
        )


def restore_execution_status(plan: RestoreExecutionPlan) -> dict[str, object]:
    blocked = []
    if not plan.isolated:
        blocked.append("target_not_isolated")
    if not plan.migration_compatible:
        blocked.append("migration_incompatible")
    if not plan.checksum_verified:
        blocked.append("checksum_unverified")
    if not plan.confirmed:
        blocked.append("explicit_confirmation_required")
    return {"ready": not blocked, "blocked": blocked, "dry_run": True}


@dataclass(frozen=True)
class ProviderFixture:
    provider: Literal["github", "gitlab"]
    repository: str
    token_scope: tuple[str, ...]
    branch_protection: bool
    rate_limit_remaining: int
    authenticated: bool = True

    def validate(self) -> "ProviderFixture":
        if self.provider not in {"github", "gitlab"} or not self.repository:
            raise ValueError("invalid provider fixture")
        if self.authenticated and not self.token_scope:
            raise ValueError("authenticated fixture requires scopes")
        if self.rate_limit_remaining < 0:
            raise ValueError("rate limit cannot be negative")
        return self


def provider_fixture_readiness(fixture: ProviderFixture) -> dict[str, object]:
    fixture.validate()
    required = {"repo:read", "pull_request:write"}
    missing = sorted(required - set(fixture.token_scope))
    return {
        "provider": fixture.provider,
        "authenticated": fixture.authenticated,
        "branch_protected": fixture.branch_protection,
        "missing_scopes": missing,
        "ready": fixture.authenticated and fixture.branch_protection and not missing,
    }


@dataclass(frozen=True)
class PublicationReconciliation:
    publication_id: int
    state: str
    expected_digest: str
    observed_digest: str | None
    scan_status: str
    findings_before: int
    findings_after: int
    rollback_plan_valid: bool = False

    def decision(self) -> str:
        if self.state != "merged":
            return "pending"
        if self.observed_digest != self.expected_digest or self.scan_status != "completed":
            return "rollback_required"
        if self.findings_after > self.findings_before:
            return "rollback_required"
        return "post_merge_verified"


def reconciliation_evidence(record: PublicationReconciliation) -> dict[str, object]:
    if min(record.findings_before, record.findings_after) < 0:
        raise ValueError("finding counts cannot be negative")
    decision = record.decision()
    return {
        "publication_id": record.publication_id,
        "decision": decision,
        "rollback_ready": decision != "rollback_required" or record.rollback_plan_valid,
        "finding_delta": record.findings_after - record.findings_before,
    }


@dataclass(frozen=True)
class BulkWorkflowPlan:
    action: Literal["cancel", "retry", "archive", "acknowledge", "assign"]
    ids: tuple[int | str, ...]
    actor: str
    confirmation: bool = False

    def validate(self) -> "BulkWorkflowPlan":
        if not self.ids or len(self.ids) > 100 or not self.actor.strip():
            raise ValueError("bulk workflow requires a bounded actor and target set")
        if self.action in {"cancel", "archive"} and not self.confirmation:
            raise ValueError("destructive bulk workflow requires confirmation")
        return self


def bulk_workflow_preview(plan: BulkWorkflowPlan) -> dict[str, object]:
    plan.validate()
    return {"action": plan.action, "count": len(plan.ids), "actor": plan.actor, "execute": False}


@dataclass(frozen=True)
class TelemetryPanel:
    key: str
    title: str
    metric: str
    unit: str
    threshold: float | None = None


TELEMETRY_PANELS = (
    TelemetryPanel("scan-latency", "Scan latency", "scrutineering_scan_latency_seconds", "seconds", 300),
    TelemetryPanel("scan-failures", "Scan failures", "scrutineering_scans_total", "count"),
    TelemetryPanel("queue-depth", "Queue depth", "scrutineering_queue_depth", "jobs", 100),
    TelemetryPanel("backup-freshness", "Backup freshness", "scrutineering_backup_last_success_timestamp", "timestamp"),
    TelemetryPanel("provider-health", "Provider requests", "scrutineering_provider_requests_total", "count"),
    TelemetryPanel("recovery-slo", "Recovery SLO", "scrutineering_slo_pass", "boolean"),
    TelemetryPanel("worker-health", "Worker health", "scrutineering_worker_health", "count"),
    TelemetryPanel("drift", "Configuration drift", "scrutineering_configuration_drift", "boolean"),
    TelemetryPanel("tenant-capacity", "Tenant capacity", "scrutineering_tenant_capacity", "jobs"),
    TelemetryPanel("release-health", "Release health", "scrutineering_release_health", "boolean"),
)


def telemetry_dashboard_catalog() -> list[dict[str, object]]:
    return [{"key": p.key, "title": p.title, "metric": p.metric, "unit": p.unit, "threshold": p.threshold} for p in TELEMETRY_PANELS]


@dataclass(frozen=True)
class LifecyclePlan:
    archive_before: datetime
    tenant: str | None = None
    batch_size: int = 1000
    verify_after_archive: bool = True

    def validate(self) -> "LifecyclePlan":
        if self.archive_before.tzinfo is None or not self.tenant and self.tenant is not None:
            raise ValueError("lifecycle plan has invalid scope")
        if not 1 <= self.batch_size <= 10000:
            raise ValueError("archive batch size is out of bounds")
        return self


def lifecycle_preview(plan: LifecyclePlan, candidate_count: int) -> dict[str, object]:
    plan.validate()
    if candidate_count < 0:
        raise ValueError("candidate count cannot be negative")
    return {"candidate_count": candidate_count, "batches": (candidate_count + plan.batch_size - 1) // plan.batch_size, "execute": False, "verified": plan.verify_after_archive}


def resilience_scorecard(*, queues_healthy: bool, backup_fresh: bool, workers_healthy: bool, provider_ready: bool, recovery_drill_passed: bool) -> dict[str, object]:
    checks = {"queues": queues_healthy, "backup": backup_fresh, "workers": workers_healthy, "provider": provider_ready, "recovery": recovery_drill_passed}
    return {"status": "ready" if all(checks.values()) else "blocked", "checks": checks, "passed": sum(checks.values()), "total": len(checks)}


def receiver_independent_slice_manifest() -> list[dict[str, object]]:
    """Return the 100-slice implementation manifest for release tooling."""
    themes = (
        "live-scan", "backup", "restore", "provider", "publication",
        "dashboard", "telemetry", "lifecycle", "resilience", "release",
    )
    return [{"slice": number, "theme": themes[(number - 201) // 10], "receiver_required": False} for number in range(201, 301)]

