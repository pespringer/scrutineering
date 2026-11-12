"""Authenticated, read-only API used by the operations dashboard."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import uuid
from urllib.request import urlopen
import os

from fastapi import APIRouter, HTTPException, Query, Request
from sqlalchemy.exc import IntegrityError
from pydantic import BaseModel, Field, field_validator
from typing import Literal

from src.db.connection import get_session
from src.db.models import AuditEventType, AuditLog, Image, Remediation, RemediationActionType, RemediationAlertDelivery, RemediationAlertEvidence, RemediationPublication, RemediationRecoveryRequest, RemediationReconciliationRun, RemediationReleaseEvidence, RemediationStatus, RemediationWebhookEvent, Scan, ScanFinding, ScanStatus, Severity, SeveritySnapshot
from src.db.repositories import AuditLogRepository, RemediationRepository
from src.remediation.approval import approval_token_hash, issue_approval, verify_approval
from src.remediation.worker import execute_approved_remediation
from src.remediation.post_merge import evaluate_post_merge
from src.remediation.events import publication_event_exists
from src.remediation.recovery import transition_recovery_status
from src.remediation.publication import build_publication_plan
from src.remediation.rollback import build_rollback_plan
from src.remediation.provider_publishers import publish_validated_plan
from src.remediation.provider_callbacks import normalize_callback, verify_signature
from src.remediation.reconciliation import publication_age_seconds, publication_is_stale
from src.remediation.evidence_retention import retention_cutoff, retention_days
from src.remediation.evidence_export import sign_export
from src.remediation.provider_auth import credential_diagnostics
from src.remediation.evidence_archive import manifest
from src.telemetry.scan_metrics import record_provider_callback, set_stale_publications
from src.scan.image_identity import parse_image_reference
from src.scan.tasks import app as celery_app, enqueue_scan


router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


class ScanRequest(BaseModel):
    image_name: str = Field(min_length=1, max_length=512)
    priority: str = Field(default="normal", pattern="^(low|normal|high)$")

    @field_validator("image_name")
    @classmethod
    def image_name_must_be_trimmed(cls, value: str) -> str:
        value = value.strip()
        if not value or any(char.isspace() for char in value):
            raise ValueError("image_name must be a single image reference")
        return value


class RemediationRequest(BaseModel):
    image_id: int = Field(gt=0)
    finding_ids: list[int] = Field(min_length=1, max_length=50)


class ApprovalTokenRequest(BaseModel):
    ttl_seconds: int = Field(default=900, ge=60, le=3600)


class ApprovalRequest(BaseModel):
    token: str = Field(min_length=32, max_length=1024)


class PublicationPlanRequest(BaseModel):
    provider: str = Field(min_length=1, max_length=32)
    repository: str = Field(min_length=1, max_length=256)
    head: str = Field(min_length=1, max_length=256)
    base: str = Field(default="main", max_length=64)
    idempotency_key: str = Field(min_length=1, max_length=256)
    commit: str = Field(min_length=7, max_length=64)
    evidence_verified: bool = False


class PostMergeVerificationRequest(BaseModel):
    expected_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    observed_digest: str | None = Field(default=None, pattern=r"^sha256:[a-f0-9]{64}$")
    scan_status: Literal["completed", "failed", "partial", "pending"]
    findings_before: int = Field(ge=0, le=100000)
    findings_after: int = Field(ge=0, le=100000)
    merge_commit: str | None = Field(default=None, pattern=r"^[a-f0-9]{40}$")
    evidence_key: str = Field(default="", max_length=128)


class PublicationRecoveryRequest(BaseModel):
    action: Literal["request_callback", "mark_manual_review"]
    idempotency_key: str = Field(min_length=1, max_length=256)
    note: str = Field(default="", max_length=2000)


class RecoveryStatusRequest(BaseModel):
    status: Literal["acknowledged", "completed", "failed"]
    reason_code: Literal["operator_reviewed", "provider_confirmed", "manual_intervention", "validation_failed", "timeout", "other"] = "operator_reviewed"
    note: str = Field(default="", max_length=2000)

    @field_validator("note")
    @classmethod
    def failure_requires_context(cls, value: str, info):
        if info.data.get("status") == "failed" and not value.strip():
            raise ValueError("failed recovery status requires a note")
        return value


class AlertEvidenceRequest(BaseModel):
    delivery_key: str = Field(min_length=1, max_length=128)
    receiver: str = Field(min_length=1, max_length=128)
    status: Literal["delivered", "failed", "retrying"]
    response_code: int | None = Field(default=None, ge=100, le=599)
    attempt: int = Field(default=1, ge=1, le=100)
    detail: dict = Field(default_factory=dict)


class AlertBulkRequest(BaseModel):
    delivery_ids: list[int] = Field(min_length=1, max_length=100)


class PublicationRequest(PublicationPlanRequest):
    title: str = Field(min_length=1, max_length=256)
    body: str = Field(min_length=1, max_length=10000)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _value(value) -> str | None:
    return value.value if hasattr(value, "value") else value


def _severity_counts(findings: list[ScanFinding]) -> dict[str, int]:
    counts = Counter((_value(finding.severity) or "unknown") for finding in findings)
    return {severity: counts.get(severity, 0) for severity in ("critical", "high", "medium", "low")}


def _scan_payload(scan: Scan) -> dict:
    return {
        "scan_id": scan.scan_id,
        "image_name": scan.image.full_name if scan.image else "unknown",
        "status": _value(scan.status),
        "started_at": _iso(scan.started_at),
        "completed_at": _iso(scan.completed_at),
        "findings": scan.total_findings or 0,
        "critical_count": scan.critical_count or 0,
        "high_count": scan.high_count or 0,
        "medium_count": scan.medium_count or 0,
        "low_count": scan.low_count or 0,
    }


def _image_payload(image: Image, findings: list[ScanFinding]) -> dict:
    counts = _severity_counts(findings)
    return {
        "id": image.id,
        "registry": _value(image.registry_name),
        "repo_name": image.repo_name,
        "tag": image.tag,
        "last_scan_at": _iso(image.last_scan_at),
        "last_scan_id": image.last_scan_id,
        "open_findings": len(findings),
        "critical_count": counts["critical"],
        "high_count": counts["high"],
        "medium_count": counts["medium"],
        "low_count": counts["low"],
    }


def _finding_payload(finding: ScanFinding) -> dict:
    severity = _value(finding.severity)
    return {
        "id": finding.id,
        "fingerprint": finding.fingerprint,
        "cve_id": finding.cve_id,
        "package_name": finding.package_name,
        "package_version": finding.package_version,
        "package_type": finding.package_type,
        "severity": severity.upper() if severity else "UNKNOWN",
        "title": finding.title,
        "description": finding.description,
        "fixed_version": finding.fixed_version,
        "fix_available": bool(finding.fix_available),
        "first_seen": _iso(finding.first_seen),
        "last_seen": _iso(finding.last_seen),
        "remediated": bool(finding.remediated),
    }


def _page(items: list[dict], limit: int, offset: int, total: int) -> dict:
    return {"items": items, "limit": limit, "offset": offset, "count": len(items), "total": total}


def _severity_filter(value: str | None) -> Severity | None:
    if not value or value.lower() == "all":
        return None
    try:
        return Severity(value.lower())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="invalid severity") from exc


def _require_role(request: Request, *allowed: str) -> None:
    roles = set(getattr(request.state, "principal_roles", []))
    if not roles.intersection({*allowed, "admin"}):
        raise HTTPException(status_code=403, detail="operator_role_required")


def _record_operator_event(session, request: Request, event_type: AuditEventType, entity_id: str, detail: dict, entity_type: str = "scan") -> None:
    AuditLogRepository.record(
        session,
        event_type=event_type,
        entity_type=entity_type,
        entity_id=entity_id,
        detail=detail,
        actor=getattr(request.state, "principal_id", "dashboard-service"),
        actor_kind="user" if getattr(request.state, "auth_method", "") == "oidc_proxy" else "system",
    )


def _apply_post_merge_result(session, publication: RemediationPublication, result: dict, merge_commit: str | None) -> str:
    """Persist verification and append its lifecycle event exactly once."""
    publication.verification_status = str(result["status"])
    publication.verification_detail = result
    event_type = "rollback_required" if result["status"] == "rollback_required" else "post_merge_verified"
    if result["status"] == "rollback_required":
        if merge_commit:
            try:
                publication.rollback_command = list(build_rollback_plan(merge_commit).command)
            except ValueError:
                publication.rollback_command = []
    else:
        publication.rollback_command = []
    events = RemediationRepository.list_events(session, publication.remediation_id)
    event_detail = {**result, "publication_id": publication.id}
    if not publication_event_exists(events, event_type=event_type, publication_id=publication.id, detail=result):
        RemediationRepository.append_event(session, {
            "remediation_id": publication.remediation_id,
            "event_type": event_type,
            "sequence": len(events) + 1,
            "detail": event_detail,
        })
    return event_type


def _remediation_actions(findings: list[ScanFinding]) -> list[dict]:
    return [{
        "finding_id": finding.id,
        "action_type": RemediationActionType.DEPENDENCY_UPDATE.value,
        "package_name": finding.package_name,
        "from_version": finding.package_version,
        "to_version": finding.fixed_version,
        "cve_id": finding.cve_id,
        "severity": _value(finding.severity),
        "safe_to_apply": bool(finding.fix_available and finding.fixed_version),
    } for finding in findings]


def _remediation_payload(remediation: Remediation, actions: list[dict] | None = None) -> dict:
    stale_after_seconds = min(max(int(os.environ.get("REMEDIATION_PUBLICATION_STALE_SECONDS", "900")), 60), 604800)
    return {
        "id": remediation.id,
        "image_id": remediation.image_id,
        "status": _value(remediation.status),
        "finding_count": remediation.finding_count,
        "target_severities": remediation.target_severities,
        "approved_by": remediation.approved_by,
        "approved_at": _iso(remediation.approved_at),
        "stale_publication_count": sum(publication_is_stale(publication, stale_after_seconds=stale_after_seconds) for publication in remediation.publications),
        "actions": actions if actions is not None else [{
            "id": action.id,
            "action_type": _value(action.action_type),
            "file_path": action.file_path,
            "before_value": action.before_value,
            "after_value": action.after_value,
            "success": action.success,
            "detail": action.detail,
        } for action in remediation.actions],
        "publications": [{
            "id": publication.id, "provider": publication.provider,
            "repository": publication.repository, "status": publication.status,
            "url": publication.url, "number": publication.provider_number,
            "merged_at": _iso(publication.merged_at),
            "verification_status": publication.verification_status,
            "scan_status": publication.scan_status,
            "findings_before": publication.findings_before,
            "findings_after": publication.findings_after,
            "rollback_command": publication.rollback_command,
            "stale": publication_is_stale(publication, stale_after_seconds=min(max(int(os.environ.get("REMEDIATION_PUBLICATION_STALE_SECONDS", "900")), 60), 604800)),
            "recovery_requests": [{"id": recovery.id, "action": recovery.action, "status": recovery.status, "note": recovery.note, "error_message": recovery.error_message, "requested_at": _iso(recovery.requested_at), "acknowledged_at": _iso(recovery.acknowledged_at), "completed_at": _iso(recovery.completed_at)} for recovery in publication.recovery_requests],
            "release_evidence": [{"id": evidence.id, "evidence_key": evidence.evidence_key, "status": evidence.status, "expected_digest": evidence.expected_digest, "observed_digest": evidence.observed_digest, "scan_status": evidence.scan_status, "findings_before": evidence.findings_before, "findings_after": evidence.findings_after, "created_at": _iso(evidence.created_at), "verified_at": _iso(evidence.verified_at)} for evidence in publication.release_evidence],
            "alert_evidence": [{"id": evidence.id, "delivery_key": evidence.delivery_key, "receiver": evidence.receiver, "status": evidence.status, "response_code": evidence.response_code, "attempt": evidence.attempt, "detail": evidence.detail, "created_at": _iso(evidence.created_at)} for evidence in publication.alert_evidence],
        } for publication in remediation.publications],
    }


@router.get("/posture/summary")
def posture_summary() -> dict:
    with get_session() as session:
        images = session.query(Image).filter_by(active=True).all()
        findings = session.query(ScanFinding).filter_by(remediated=False).all()
        latest_scan = session.query(Scan).order_by(Scan.started_at.desc()).first()

    counts = _severity_counts(findings)
    return {
        "total_scanned_images": len(images),
        "total_findings": len(findings),
        "critical_count": counts["critical"],
        "high_count": counts["high"],
        "medium_count": counts["medium"],
        "low_count": counts["low"],
        "fixable_count": sum(1 for finding in findings if finding.fix_available),
        "last_scan_at": _iso(latest_scan.completed_at if latest_scan and latest_scan.completed_at else latest_scan.started_at if latest_scan else None),
        "last_scan_status": _value(latest_scan.status) if latest_scan else None,
    }


@router.get("/posture/trend")
def posture_trend(days: int = Query(default=30, ge=1, le=365)) -> list[dict]:
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days)
    with get_session() as session:
        snapshots = session.query(SeveritySnapshot).filter(SeveritySnapshot.snapshot_date >= cutoff).all()

    grouped: dict[str, dict[str, int]] = defaultdict(lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0})
    for snapshot in snapshots:
        date = snapshot.snapshot_date.date().isoformat()
        grouped[date]["critical"] += snapshot.critical_count or 0
        grouped[date]["high"] += snapshot.high_count or 0
        grouped[date]["medium"] += snapshot.medium_count or 0
        grouped[date]["low"] += snapshot.low_count or 0
    return [{"date": date, **grouped[date]} for date in sorted(grouped)]


@router.get("/scans")
def scan_history(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    status: str | None = Query(default=None),
    search: str | None = Query(default=None, max_length=200),
) -> dict:
    with get_session() as session:
        query = session.query(Scan).join(Image)
        if status and status.lower() != "all":
            try:
                ScanStatus(status.lower())
                query = query.filter(Scan.status == status.lower())
            except ValueError as exc:
                raise HTTPException(status_code=400, detail="invalid scan status") from exc
        if search:
            query = query.filter(Image.repo_name.ilike(f"%{search.strip()}%"))
        total = query.order_by(None).count()
        scans = query.order_by(Scan.started_at.desc()).offset(offset).limit(limit).all()
    return _page([_scan_payload(scan) for scan in scans], limit, offset, total)


@router.get("/scans/{scan_id}")
def scan_status(scan_id: str) -> dict:
    with get_session() as session:
        scan = session.query(Scan).filter_by(scan_id=scan_id).first()
        if scan is None:
            raise HTTPException(status_code=404, detail="scan_not_found")
        return _scan_payload(scan)


@router.post("/scans/{scan_id}/cancel")
def cancel_scan(scan_id: str, request: Request) -> dict:
    _require_role(request, "operator", "security-operator")
    with get_session() as session:
        scan = session.query(Scan).filter_by(scan_id=scan_id).first()
        if scan is None:
            raise HTTPException(status_code=404, detail="scan_not_found")
        if scan.status in {ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED}:
            return _scan_payload(scan)
        scan.status = ScanStatus.CANCELLED.value
        scan.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
        _record_operator_event(session, request, AuditEventType.SCAN_CANCELLED, scan_id, {"action": "cancel_scan"})
    celery_app.control.revoke(scan_id, terminate=False)
    return {"scan_id": scan_id, "status": "cancelled"}


@router.post("/scans", status_code=202)
def start_scan(payload: ScanRequest, request: Request) -> dict:
    _require_role(request, "operator", "security-operator")
    scan_id = uuid.uuid4().hex
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    identity = parse_image_reference(payload.image_name)
    try:
        with get_session() as session:
            image = session.query(Image).filter_by(
                registry_name=identity.registry,
                repo_name=identity.repo_name,
                tag=identity.tag,
            ).first()
            if image is None:
                image = Image(
                    registry_name=identity.registry,
                    repo_name=identity.repo_name,
                    tag=identity.tag,
                    digest=identity.digest,
                )
                session.add(image)
                session.flush()
            image.last_scan_id = scan_id
            session.add(Scan(
                scan_id=scan_id,
                image_id=image.id,
                status=ScanStatus.PENDING.value,
                started_at=now,
                image_digest=identity.digest,
            ))
            _record_operator_event(session, request, AuditEventType.SCAN_STARTED, scan_id, {"action": "start_scan", "image_name": payload.image_name, "priority": payload.priority})
        task = enqueue_scan(payload.image_name, priority=payload.priority, scan_id=scan_id)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="scan_queue_unavailable") from exc
    return {"scan_id": scan_id, "task_id": task.id, "image_name": payload.image_name, "status": "pending"}


@router.get("/images")
def image_inventory(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    search: str | None = Query(default=None, max_length=200),
    severity: str | None = Query(default=None),
) -> dict:
    severity_value = _severity_filter(severity)
    with get_session() as session:
        query = session.query(Image).filter_by(active=True)
        if search:
            query = query.filter(Image.repo_name.ilike(f"%{search.strip()}%"))
        if severity_value:
            query = query.filter(Image.id.in_(session.query(ScanFinding.image_id).filter_by(remediated=False, severity=severity_value.value)))
        total = query.order_by(None).count()
        images = query.order_by(Image.repo_name.asc()).offset(offset).limit(limit).all()
        image_ids = [image.id for image in images]
        findings = session.query(ScanFinding).filter(
            ScanFinding.image_id.in_(image_ids), ScanFinding.remediated.is_(False),
        ).all() if image_ids else []
    findings_by_image: dict[int, list[ScanFinding]] = defaultdict(list)
    for finding in findings:
        findings_by_image[finding.image_id].append(finding)
    return _page([_image_payload(image, findings_by_image[image.id]) for image in images], limit, offset, total)


@router.get("/images/{image_id}")
def image_detail(
    image_id: int,
    severity: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict:
    severity_value = _severity_filter(severity)
    with get_session() as session:
        image = session.get(Image, image_id)
        if image is None:
            raise HTTPException(status_code=404, detail="image_not_found")
        query = session.query(ScanFinding).filter_by(image_id=image_id, remediated=False)
        if severity_value:
            query = query.filter(ScanFinding.severity == severity_value.value)
        total = query.order_by(None).count()
        findings = query.order_by(ScanFinding.severity.asc(), ScanFinding.id.asc()).offset(offset).limit(limit).all()
        all_findings = session.query(ScanFinding).filter_by(image_id=image_id, remediated=False).all()
    return {
        "image": _image_payload(image, all_findings),
        "findings": [_finding_payload(finding) for finding in findings],
        "findings_page": _page([_finding_payload(finding) for finding in findings], limit, offset, total),
    }


@router.get("/session")
def dashboard_session(request: Request) -> dict:
    return {
        "authenticated": True,
        "auth_method": getattr(request.state, "auth_method", "api_key"),
        "subject": getattr(request.state, "principal_id", "dashboard-service"),
        "email": getattr(request.state, "principal_email", None),
        "roles": getattr(request.state, "principal_roles", []),
    }


@router.get("/permissions")
def dashboard_permissions(request: Request) -> dict:
    roles = set(getattr(request.state, "principal_roles", []))
    elevated = bool(roles.intersection({"admin", "security-operator"}))
    return {
        "roles": sorted(roles),
        "can_view": True,
        "can_manage_scans": bool(roles.intersection({"admin", "operator", "security-operator"})),
        "can_cancel_scans": bool(roles.intersection({"admin", "operator", "security-operator"})),
        "can_remediate": elevated or "remediator" in roles,
    }


@router.get("/provider-credentials/health")
def provider_credentials_health(request: Request) -> dict:
    _require_role(request, "security-operator", "admin")
    return {"providers": [credential_diagnostics("github"), credential_diagnostics("gitlab")]}


@router.get("/audit")
def dashboard_audit(
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    actor: str | None = Query(default=None, max_length=128),
    event_type: str | None = Query(default=None, max_length=64),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
) -> dict:
    with get_session() as session:
        query = session.query(AuditLog)
        if actor:
            query = query.filter(AuditLog.actor == actor)
        if event_type:
            query = query.filter(AuditLog.event_type == event_type.lower())
        if since:
            query = query.filter(AuditLog.timestamp >= since.replace(tzinfo=None))
        if until:
            query = query.filter(AuditLog.timestamp <= until.replace(tzinfo=None))
        total = query.order_by(None).count()
        records = query.order_by(AuditLog.timestamp.desc(), AuditLog.id.desc()).offset(offset).limit(limit).all()
    items = [{
        "id": record.id,
        "timestamp": _iso(record.timestamp),
        "event_type": _value(record.event_type),
        "entity_type": record.entity_type,
        "entity_id": record.entity_id,
        "detail": record.detail,
        "actor": record.actor,
        "actor_kind": record.actor_kind,
    } for record in records]
    return _page(items, limit, offset, total)


@router.get("/audit/export")
def dashboard_audit_export(request: Request, limit: int = Query(default=1000, ge=1, le=5000), actor: str | None = Query(default=None), event_type: str | None = Query(default=None), since: datetime | None = Query(default=None), until: datetime | None = Query(default=None)) -> dict:
    _require_role(request, "security-operator", "admin")
    with get_session() as session:
        query = session.query(AuditLog)
        if actor: query = query.filter(AuditLog.actor == actor)
        if event_type: query = query.filter(AuditLog.event_type == event_type.lower())
        if since: query = query.filter(AuditLog.timestamp >= since.replace(tzinfo=None))
        if until: query = query.filter(AuditLog.timestamp <= until.replace(tzinfo=None))
        records = query.order_by(AuditLog.timestamp.asc(), AuditLog.id.asc()).limit(limit).all()
    items = [{"id": record.id, "timestamp": _iso(record.timestamp), "event_type": _value(record.event_type), "entity_type": record.entity_type, "entity_id": record.entity_id, "detail": record.detail, "actor": record.actor, "actor_kind": record.actor_kind, "record_hash": record.record_hash, "previous_hash": record.previous_hash} for record in records]
    canonical = json.dumps(items, sort_keys=True, separators=(",", ":")).encode()
    return {"format": "scrutineering-audit-v1", "count": len(items), "sha256": hashlib.sha256(canonical).hexdigest(), "records": items}


@router.post("/remediations/preview")
def remediation_preview(payload: RemediationRequest, request: Request) -> dict:
    _require_role(request, "remediator", "security-operator")
    with get_session() as session:
        image = session.get(Image, payload.image_id)
        findings = session.query(ScanFinding).filter(
            ScanFinding.image_id == payload.image_id,
            ScanFinding.id.in_(payload.finding_ids),
            ScanFinding.remediated.is_(False),
        ).order_by(ScanFinding.severity.asc(), ScanFinding.id.asc()).all()
    if image is None:
        raise HTTPException(status_code=404, detail="image_not_found")
    if len(findings) != len(set(payload.finding_ids)):
        raise HTTPException(status_code=400, detail="findings_must_belong_to_image")
    actions = _remediation_actions(findings)
    return {
        "image": _image_payload(image, findings),
        "finding_ids": [finding.id for finding in findings],
        "actions": actions,
        "actionable_count": sum(action["safe_to_apply"] for action in actions),
        "requires_approval": True,
        "mutates_state": False,
    }


@router.get("/remediations")
def list_remediations(
    request: Request,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    status: str | None = Query(default=None, max_length=32),
) -> dict:
    _require_role(request, "remediator", "security-operator")
    with get_session() as session:
        query = session.query(Remediation)
        if status:
            try:
                query = query.filter(Remediation.status == RemediationStatus(status.lower()))
            except ValueError as exc:
                raise HTTPException(status_code=400, detail="invalid_remediation_status") from exc
        total = query.order_by(None).count()
        records = query.order_by(Remediation.created_at.desc(), Remediation.id.desc()).offset(offset).limit(limit).all()
        items = [_remediation_payload(record) for record in records]
    return _page(items, limit, offset, total)


@router.get("/remediations/publications/reconciliation")
def publication_reconciliation(request: Request, status: str | None = Query(default=None), recovery_status: str | None = Query(default=None), min_attempts: int = Query(default=0, ge=0, le=100), limit: int = Query(default=100, ge=1, le=250)) -> dict:
    _require_role(request, "security-operator")
    stale_after_seconds = min(max(int(os.environ.get("REMEDIATION_PUBLICATION_STALE_SECONDS", "900")), 60), 604800)
    with get_session() as session:
        query = session.query(RemediationPublication).filter(RemediationPublication.status.in_(["pending", "failed", "merged"]))
        if status:
            if status not in {"pending", "failed", "merged", "stale"}:
                raise HTTPException(status_code=400, detail="invalid_reconciliation_status")
            if status != "stale":
                query = query.filter(RemediationPublication.status == status)
        records = query.order_by(RemediationPublication.created_at.asc()).limit(limit).all()
    stale_records = [record for record in records if publication_is_stale(record, stale_after_seconds=stale_after_seconds)]
    set_stale_publications(len(stale_records))
    if status == "stale":
        records = stale_records
    items = [{"id": record.id, "remediation_id": record.remediation_id, "provider": record.provider, "repository": record.repository, "status": record.status, "url": record.url, "verification_status": record.verification_status, "scan_status": record.scan_status, "rollback_command": record.rollback_command, "age_seconds": publication_age_seconds(record), "stale": record in stale_records, "stale_after_seconds": stale_after_seconds, "recovery_requests": [{"id": recovery.id, "status": recovery.status, "attempts": recovery.attempts, "max_attempts": recovery.max_attempts, "next_attempt_at": _iso(recovery.next_attempt_at)} for recovery in record.recovery_requests if (not recovery_status or recovery.status == recovery_status) and recovery.attempts >= min_attempts]} for record in records]
    if recovery_status or min_attempts:
        items = [item for item in items if item["recovery_requests"]]
    return {"items": items, "count": len(items), "stale_count": len(stale_records), "stale_after_seconds": stale_after_seconds, "evidence_retention_days": retention_days(), "evidence_cutoff": retention_cutoff().isoformat()}


@router.get("/remediations/publications/reconciliation/health")
def publication_reconciliation_health(request: Request) -> dict:
    _require_role(request, "security-operator")
    with get_session() as session:
        run = session.query(RemediationReconciliationRun).order_by(RemediationReconciliationRun.started_at.desc()).first()
    if run is None:
        return {"status": "never_run", "last_run": None}
    return {"status": run.status, "last_run": {"id": run.id, "status": run.status, "discovered": run.discovered, "events_recorded": run.events_recorded, "error_message": run.error_message, "started_at": _iso(run.started_at), "completed_at": _iso(run.completed_at)}}


@router.post("/remediations", status_code=201)
def create_remediation(payload: RemediationRequest, request: Request) -> dict:
    _require_role(request, "remediator", "security-operator")
    with get_session() as session:
        image = session.get(Image, payload.image_id)
        findings = session.query(ScanFinding).filter(
            ScanFinding.image_id == payload.image_id,
            ScanFinding.id.in_(payload.finding_ids),
            ScanFinding.remediated.is_(False),
            ScanFinding.fix_available.is_(True),
        ).all()
        if image is None:
            raise HTTPException(status_code=404, detail="image_not_found")
        if len(findings) != len(set(payload.finding_ids)):
            raise HTTPException(status_code=400, detail="all_findings_need_available_fixes")
        severities = Counter(_value(finding.severity) or "unknown" for finding in findings)
        remediation = RemediationRepository.create(
            session,
            image_id=image.id,
            finding_count=len(findings),
            target_severities=dict(severities),
        )
        remediation.status = RemediationStatus.REQUIRES_REVIEW
        actions = _remediation_actions(findings)
        for finding, action in zip(findings, actions):
            RemediationRepository.add_action(
                session, remediation.id, RemediationActionType.DEPENDENCY_UPDATE,
                before_value=finding.package_version, after_value=finding.fixed_version,
                detail={"finding_id": finding.id, "package_name": finding.package_name, "cve_id": finding.cve_id},
            )
        _record_operator_event(session, request, AuditEventType.REMEDIATION_STARTED, str(remediation.id), {"action": "remediation_requested", "finding_ids": payload.finding_ids}, entity_type="remediation")
        return _remediation_payload(remediation, actions)


@router.get("/remediations/{remediation_id}")
def remediation_detail(remediation_id: int, request: Request) -> dict:
    _require_role(request, "remediator", "security-operator")
    with get_session() as session:
        remediation = RemediationRepository.get_by_id(session, remediation_id)
        if remediation is None:
            raise HTTPException(status_code=404, detail="remediation_not_found")
        return _remediation_payload(remediation)


@router.get("/remediations/{remediation_id}/events")
def remediation_events(remediation_id: int, request: Request) -> dict:
    _require_role(request, "remediator", "security-operator")
    with get_session() as session:
        if session.get(Remediation, remediation_id) is None:
            raise HTTPException(status_code=404, detail="remediation_not_found")
        events = RemediationRepository.list_events(session, remediation_id)
    return {"remediation_id": remediation_id, "events": [{
        "id": event.id, "event_type": event.event_type, "sequence": event.sequence,
        "detail": event.detail, "created_at": _iso(event.created_at),
    } for event in events]}


@router.post("/remediations/{remediation_id}/approval-token")
def remediation_approval_token(remediation_id: int, payload: ApprovalTokenRequest, request: Request) -> dict:
    _require_role(request, "security-operator")
    secret = os.environ.get("REMEDIATION_APPROVAL_SECRET", "")
    if not secret:
        raise HTTPException(status_code=503, detail="remediation_approval_not_configured")
    with get_session() as session:
        remediation = session.get(Remediation, remediation_id)
        if remediation is None:
            raise HTTPException(status_code=404, detail="remediation_not_found")
        if _value(remediation.status) != RemediationStatus.REQUIRES_REVIEW.value:
            raise HTTPException(status_code=409, detail="remediation_not_awaiting_approval")
    token = issue_approval(str(remediation_id), getattr(request.state, "principal_id", "dashboard-service"), secret, ttl_seconds=payload.ttl_seconds)
    return {"remediation_id": remediation_id, "token": token, "expires_in": payload.ttl_seconds}


@router.post("/remediations/{remediation_id}/approve")
def approve_remediation(remediation_id: int, payload: ApprovalRequest, request: Request) -> dict:
    _require_role(request, "security-operator")
    secret = os.environ.get("REMEDIATION_APPROVAL_SECRET", "")
    if not secret:
        raise HTTPException(status_code=503, detail="remediation_approval_not_configured")
    try:
        approval = verify_approval(payload.token, str(remediation_id), secret)
    except ValueError as exc:
        raise HTTPException(status_code=403, detail="invalid_approval_token") from exc
    with get_session() as session:
        remediation = session.get(Remediation, remediation_id)
        if remediation is None:
            raise HTTPException(status_code=404, detail="remediation_not_found")
        if _value(remediation.status) != RemediationStatus.REQUIRES_REVIEW.value:
            raise HTTPException(status_code=409, detail="remediation_not_awaiting_approval")
        RemediationRepository.update_status(
            session, remediation_id, RemediationStatus.ANALYZING,
            approved_by=approval["approver"], approved_at=datetime.now(timezone.utc).replace(tzinfo=None),
            approval_token_hash=approval_token_hash(payload.token),
        )
        _record_operator_event(session, request, AuditEventType.CONFIG_CHANGED, str(remediation_id), {"action": "remediation_approved", "approver": approval["approver"]}, entity_type="remediation")
        remediation = RemediationRepository.get_by_id(session, remediation_id)
        return _remediation_payload(remediation)


@router.post("/remediations/{remediation_id}/execute", status_code=202)
def execute_remediation(remediation_id: int, request: Request) -> dict:
    _require_role(request, "remediator", "security-operator")
    if os.environ.get("REMEDIATION_EXECUTION_ENABLED", "false").lower() not in {"1", "true", "yes"}:
        raise HTTPException(status_code=503, detail="remediation_execution_disabled")
    with get_session() as session:
        remediation = session.get(Remediation, remediation_id)
        if remediation is None:
            raise HTTPException(status_code=404, detail="remediation_not_found")
        if _value(remediation.status) != RemediationStatus.ANALYZING.value:
            raise HTTPException(status_code=409, detail="remediation_not_approved")
        task = execute_approved_remediation.delay(remediation_id)
        _record_operator_event(session, request, AuditEventType.CONFIG_CHANGED, str(remediation_id), {"action": "remediation_execution_requested", "task_id": task.id}, entity_type="remediation")
    return {"remediation_id": remediation_id, "task_id": task.id, "status": "queued"}


@router.post("/remediations/{remediation_id}/publication-plan")
def remediation_publication_plan(remediation_id: int, payload: PublicationPlanRequest, request: Request) -> dict:
    _require_role(request, "remediator", "security-operator")
    with get_session() as session:
        remediation = session.get(Remediation, remediation_id)
        if remediation is None:
            raise HTTPException(status_code=404, detail="remediation_not_found")
        events = RemediationRepository.list_events(session, remediation_id)
        if not any(event.event_type == "execution_ready" for event in events):
            raise HTTPException(status_code=409, detail="validated_execution_artifact_required")
    allowed = {value.strip() for value in os.environ.get("REMEDIATION_ALLOWED_REPOSITORIES", "").split(",") if value.strip()}
    try:
        plan = build_publication_plan(
            provider=payload.provider, repository=payload.repository, head=payload.head,
            base=payload.base, idempotency_key=payload.idempotency_key, commit=payload.commit,
            evidence_verified=payload.evidence_verified, allowed_repositories=allowed,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    with get_session() as session:
        _record_operator_event(session, request, AuditEventType.CONFIG_CHANGED, str(remediation_id), {"action": "publication_plan_created", "provider": plan.provider, "repository": plan.repository}, entity_type="remediation")
    return {"remediation_id": remediation_id, "provider": plan.provider, "repository": plan.repository, "head": plan.head, "base": plan.base, "idempotency_key": plan.idempotency_key, "rollback_command": list(plan.rollback_command), "publisher": "github-publisher" if plan.provider == "github" else "gitlab-publisher"}


@router.post("/remediations/{remediation_id}/publish", status_code=201)
def publish_remediation(remediation_id: int, payload: PublicationRequest, request: Request) -> dict:
    _require_role(request, "security-operator")
    if os.environ.get("REMEDIATION_PUBLICATION_ENABLED", "false").lower() not in {"1", "true", "yes"}:
        raise HTTPException(status_code=503, detail="remediation_publication_disabled")
    allowed = {value.strip() for value in os.environ.get("REMEDIATION_ALLOWED_REPOSITORIES", "").split(",") if value.strip()}
    try:
        plan = build_publication_plan(provider=payload.provider, repository=payload.repository, head=payload.head, base=payload.base, idempotency_key=payload.idempotency_key, commit=payload.commit, evidence_verified=payload.evidence_verified, allowed_repositories=allowed)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    request_hash = hashlib.sha256(json.dumps(payload.model_dump(), sort_keys=True).encode()).hexdigest()
    token = os.environ.get("GITHUB_TOKEN" if plan.provider == "github" else "GITLAB_TOKEN", "")
    with get_session() as session:
        remediation = session.get(Remediation, remediation_id)
        if remediation is None:
            raise HTTPException(status_code=404, detail="remediation_not_found")
        if not any(event.event_type == "execution_ready" for event in RemediationRepository.list_events(session, remediation_id)):
            raise HTTPException(status_code=409, detail="validated_execution_artifact_required")
        existing = session.query(RemediationPublication).filter_by(provider=plan.provider, repository=plan.repository, idempotency_key=plan.idempotency_key).first()
        if existing and existing.status == "published":
            return {"publication_id": existing.id, "status": existing.status, "number": existing.provider_number, "url": existing.url, "idempotency_key": existing.idempotency_key}
        publication = existing or RemediationPublication(remediation_id=remediation_id, provider=plan.provider, repository=plan.repository, idempotency_key=plan.idempotency_key, status="pending", request_hash=request_hash)
        session.add(publication)
        session.flush()
        try:
            result = publish_validated_plan(provider=plan.provider, repository=plan.repository, title=payload.title, body=payload.body, head=plan.head, base=plan.base, token=token, idempotency_key=plan.idempotency_key, transport=urlopen)
            publication.status = "published"
            publication.provider_number = result.number
            publication.url = result.url
            publication.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
            _record_operator_event(session, request, AuditEventType.CONFIG_CHANGED, str(remediation_id), {"action": "remediation_published", "provider": result.provider, "url": result.url}, entity_type="remediation")
            return {"publication_id": publication.id, "status": publication.status, "number": publication.provider_number, "url": publication.url, "idempotency_key": publication.idempotency_key}
        except Exception as exc:
            publication.status = "failed"
            publication.error_message = str(exc)[:1000]
            publication.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
            raise HTTPException(status_code=502, detail="provider_publication_failed") from exc


@router.post("/remediations/post-merge/verify")
def verify_post_merge(payload: PostMergeVerificationRequest, request: Request) -> dict:
    _require_role(request, "remediator", "security-operator")
    result = evaluate_post_merge(
        expected_digest=payload.expected_digest, observed_digest=payload.observed_digest,
        required_scan_status=payload.scan_status, findings_before=payload.findings_before,
        findings_after=payload.findings_after,
    )
    if result["status"] == "rollback_required":
        if not payload.merge_commit:
            return {**result, "rollback": None, "rollback_required": True}
        try:
            rollback = build_rollback_plan(payload.merge_commit)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {**result, "rollback_required": True, "rollback": {"command": list(rollback.command), "verification_required": rollback.verification_required}}
    return {**result, "rollback_required": False, "rollback": None}


@router.get("/remediations/publications/{publication_id}/recovery-preview")
def publication_recovery_preview(publication_id: int, request: Request) -> dict:
    _require_role(request, "security-operator")
    stale_after_seconds = min(max(int(os.environ.get("REMEDIATION_PUBLICATION_STALE_SECONDS", "900")), 60), 604800)
    with get_session() as session:
        publication = session.get(RemediationPublication, publication_id)
        if publication is None:
            raise HTTPException(status_code=404, detail="publication_not_found")
        stale = publication_is_stale(publication, stale_after_seconds=stale_after_seconds)
        return {
            "publication_id": publication.id,
            "status": publication.status,
            "verification_status": publication.verification_status,
            "age_seconds": publication_age_seconds(publication),
            "stale": stale,
            "stale_after_seconds": stale_after_seconds,
            "allowed_actions": ["request_callback", "mark_manual_review"] if stale else [],
            "mutates_provider": False,
            "recovery_requests": [{"id": recovery.id, "action": recovery.action, "status": recovery.status, "note": recovery.note, "attempts": recovery.attempts, "max_attempts": recovery.max_attempts, "next_attempt_at": _iso(recovery.next_attempt_at), "error_message": recovery.error_message} for recovery in publication.recovery_requests],
        }


@router.post("/remediations/publications/{publication_id}/recovery")
def request_publication_recovery(publication_id: int, payload: PublicationRecoveryRequest, request: Request) -> dict:
    _require_role(request, "security-operator")
    stale_after_seconds = min(max(int(os.environ.get("REMEDIATION_PUBLICATION_STALE_SECONDS", "900")), 60), 604800)
    with get_session() as session:
        publication = session.get(RemediationPublication, publication_id)
        if publication is None:
            raise HTTPException(status_code=404, detail="publication_not_found")
        if not publication_is_stale(publication, stale_after_seconds=stale_after_seconds):
            raise HTTPException(status_code=409, detail="publication_not_stale")
        recovery = session.query(RemediationRecoveryRequest).filter_by(publication_id=publication.id, idempotency_key=payload.idempotency_key).first()
        if recovery:
            return {"accepted": True, "replayed": True, "publication_id": publication.id, "recovery_request_id": recovery.id, "action": recovery.action, "status": recovery.status}
        recovery = RemediationRecoveryRequest(publication_id=publication.id, action=payload.action, idempotency_key=payload.idempotency_key, note=payload.note, status="requested")
        session.add(recovery)
        try:
            session.flush()
        except IntegrityError:
            session.rollback()
            recovery = session.query(RemediationRecoveryRequest).filter_by(publication_id=publication.id, idempotency_key=payload.idempotency_key).one()
            return {"accepted": True, "replayed": True, "publication_id": publication.id, "recovery_request_id": recovery.id, "action": recovery.action, "status": recovery.status}
        events = RemediationRepository.list_events(session, publication.remediation_id)
        detail = {"publication_id": publication.id, "recovery_request_id": recovery.id, "action": payload.action, "idempotency_key": payload.idempotency_key, "note": payload.note, "status": recovery.status}
        RemediationRepository.append_event(session, {
            "remediation_id": publication.remediation_id,
            "event_type": "publication_recovery_requested",
            "sequence": len(events) + 1,
            "detail": detail,
        })
        _record_operator_event(session, request, AuditEventType.CONFIG_CHANGED, str(publication.id), {"action": payload.action, "idempotency_key": payload.idempotency_key}, entity_type="publication")
        return {"accepted": True, "replayed": False, "publication_id": publication.id, "recovery_request_id": recovery.id, "action": payload.action, "status": recovery.status, "event_type": "publication_recovery_requested", "mutates_provider": False}


@router.post("/remediations/publications/{publication_id}/recovery/{recovery_id}/status")
def update_publication_recovery_status(publication_id: int, recovery_id: int, payload: RecoveryStatusRequest, request: Request) -> dict:
    _require_role(request, "security-operator")
    with get_session() as session:
        recovery = session.query(RemediationRecoveryRequest).filter_by(id=recovery_id, publication_id=publication_id).first()
        if recovery is None:
            raise HTTPException(status_code=404, detail="recovery_request_not_found")
        try:
            target = transition_recovery_status(recovery.status, payload.status)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail="invalid_recovery_transition") from exc
        if target == recovery.status:
            return {"accepted": True, "recovery_request_id": recovery.id, "status": recovery.status, "replayed": True}
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        recovery.status = target
        recovery.note = payload.note or recovery.note
        if target == "acknowledged":
            recovery.acknowledged_at = now
        if target in {"completed", "failed"}:
            recovery.completed_at = now
            if target == "failed":
                recovery.error_message = payload.note or "operator marked recovery failed"
        publication = session.get(RemediationPublication, publication_id)
        events = RemediationRepository.list_events(session, publication.remediation_id)
        RemediationRepository.append_event(session, {"remediation_id": publication.remediation_id, "event_type": "publication_recovery_status_changed", "sequence": len(events) + 1, "detail": {"publication_id": publication_id, "recovery_request_id": recovery.id, "status": target, "reason_code": payload.reason_code, "note": payload.note}})
        _record_operator_event(session, request, AuditEventType.CONFIG_CHANGED, str(publication_id), {"action": "recovery_status_changed", "recovery_request_id": recovery.id, "status": target}, entity_type="publication")
        return {"accepted": True, "recovery_request_id": recovery.id, "status": target, "replayed": False}


@router.post("/remediations/publications/{publication_id}/evidence")
def attach_publication_evidence(publication_id: int, payload: PostMergeVerificationRequest, request: Request) -> dict:
    _require_role(request, "security-operator")
    with get_session() as session:
        publication = session.get(RemediationPublication, publication_id)
        if publication is None:
            raise HTTPException(status_code=404, detail="publication_not_found")
        if publication.status != "merged":
            raise HTTPException(status_code=409, detail="publication_not_merged")
        evidence_key = payload.evidence_key or hashlib.sha256(json.dumps(payload.model_dump(exclude={"evidence_key"}), sort_keys=True).encode()).hexdigest()
        existing_evidence = session.query(RemediationReleaseEvidence).filter_by(publication_id=publication.id, evidence_key=evidence_key).first()
        if existing_evidence:
            return {"accepted": True, "publication_id": publication.id, "evidence_id": existing_evidence.id, "evidence_key": evidence_key, "verification_status": existing_evidence.status, "replayed": True}
        publication.observed_digest = payload.observed_digest or publication.observed_digest
        publication.scan_status = payload.scan_status
        publication.findings_before = payload.findings_before
        publication.findings_after = payload.findings_after
        result = evaluate_post_merge(
            expected_digest=payload.expected_digest,
            observed_digest=payload.observed_digest,
            required_scan_status=payload.scan_status,
            findings_before=payload.findings_before,
            findings_after=payload.findings_after,
        )
        event_type = _apply_post_merge_result(session, publication, result, payload.merge_commit or publication.merge_commit)
        evidence = RemediationReleaseEvidence(publication_id=publication.id, evidence_key=evidence_key, expected_digest=payload.expected_digest, observed_digest=payload.observed_digest, scan_status=payload.scan_status, findings_before=payload.findings_before, findings_after=payload.findings_after, status=str(result["status"]), verification_detail=result, verified_at=datetime.now(timezone.utc).replace(tzinfo=None) if result["status"] == "verified" else None)
        session.add(evidence)
        session.flush()
        return {"accepted": True, "publication_id": publication.id, "evidence_id": evidence.id, "evidence_key": evidence_key, "verification_status": publication.verification_status, "event_type": event_type, "rollback_command": publication.rollback_command, "replayed": False}


@router.post("/remediations/publications/{publication_id}/alert-evidence")
def attach_alert_evidence(publication_id: int, payload: AlertEvidenceRequest, request: Request) -> dict:
    _require_role(request, "security-operator")
    with get_session() as session:
        publication = session.get(RemediationPublication, publication_id)
        if publication is None:
            raise HTTPException(status_code=404, detail="publication_not_found")
        existing = session.query(RemediationAlertEvidence).filter_by(publication_id=publication.id, delivery_key=payload.delivery_key).first()
        if existing:
            return {"accepted": True, "replayed": True, "publication_id": publication.id, "alert_evidence_id": existing.id, "status": existing.status}
        evidence = RemediationAlertEvidence(publication_id=publication.id, delivery_key=payload.delivery_key, receiver=payload.receiver, status=payload.status, response_code=payload.response_code, attempt=payload.attempt, detail=payload.detail)
        session.add(evidence)
        session.flush()
        events = RemediationRepository.list_events(session, publication.remediation_id)
        RemediationRepository.append_event(session, {"remediation_id": publication.remediation_id, "event_type": "alert_delivery_recorded", "sequence": len(events) + 1, "detail": {"publication_id": publication.id, "alert_evidence_id": evidence.id, "receiver": payload.receiver, "status": payload.status, "attempt": payload.attempt}})
        return {"accepted": True, "replayed": False, "publication_id": publication.id, "alert_evidence_id": evidence.id, "status": evidence.status}


@router.get("/remediations/publications/{publication_id}/evidence-export")
def export_publication_evidence(publication_id: int, request: Request) -> dict:
    _require_role(request, "security-operator")
    with get_session() as session:
        publication = session.get(RemediationPublication, publication_id)
        if publication is None:
            raise HTTPException(status_code=404, detail="publication_not_found")
        payload = {"publication_id": publication.id, "repository": publication.repository, "release_evidence": [{"id": item.id, "evidence_key": item.evidence_key, "status": item.status, "expected_digest": item.expected_digest, "observed_digest": item.observed_digest, "scan_status": item.scan_status, "findings_before": item.findings_before, "findings_after": item.findings_after, "created_at": _iso(item.created_at), "verified_at": _iso(item.verified_at)} for item in publication.release_evidence], "alert_evidence": [{"id": item.id, "delivery_key": item.delivery_key, "receiver": item.receiver, "status": item.status, "response_code": item.response_code, "attempt": item.attempt, "detail": item.detail, "created_at": _iso(item.created_at)} for item in publication.alert_evidence]}
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        export = {"format": "scrutineering-evidence-v1", "sha256": hashlib.sha256(canonical).hexdigest(), "evidence": payload, "archive": manifest([payload])}
        secret = os.environ.get("EVIDENCE_EXPORT_SIGNING_SECRET", "")
        if secret:
            export["signature"] = sign_export(payload, secret)
        return export


@router.get("/remediations/alert-deliveries")
def list_alert_deliveries(request: Request, status: str | None = Query(default=None), limit: int = Query(default=50, ge=1, le=250)) -> dict:
    _require_role(request, "security-operator", "admin")
    with get_session() as session:
        query = session.query(RemediationAlertDelivery)
        if status:
            if status not in {"pending", "retrying", "dead_letter", "delivered", "canceled"}:
                raise HTTPException(status_code=400, detail="invalid_alert_delivery_status")
            query = query.filter(RemediationAlertDelivery.status == status)
        records = query.order_by(RemediationAlertDelivery.created_at.desc()).limit(limit).all()
    return {"items": [{"id": record.id, "publication_id": record.publication_id, "receiver": record.receiver, "status": record.status, "attempts": record.attempts, "max_attempts": record.max_attempts, "next_attempt_at": _iso(record.next_attempt_at), "last_error": record.last_error, "created_at": _iso(record.created_at)} for record in records], "count": len(records)}


@router.post("/remediations/alert-deliveries/{delivery_id}/replay")
def replay_alert_delivery(delivery_id: int, request: Request) -> dict:
    _require_role(request, "security-operator", "admin")
    with get_session() as session:
        record = session.get(RemediationAlertDelivery, delivery_id)
        if record is None:
            raise HTTPException(status_code=404, detail="alert_delivery_not_found")
        if record.status != "dead_letter":
            raise HTTPException(status_code=409, detail="alert_delivery_not_dead_lettered")
        record.status = "pending"
        record.next_attempt_at = None
        record.last_error = None
        publication = session.get(RemediationPublication, record.publication_id)
        _record_operator_event(session, request, AuditEventType.CONFIG_CHANGED, str(record.publication_id), {"action": "alert_delivery_replay", "delivery_id": record.id}, entity_type="publication")
        return {"accepted": True, "delivery_id": record.id, "status": record.status, "publication_id": publication.id if publication else None}


@router.post("/remediations/alert-deliveries/cancel")
def cancel_alert_deliveries(payload: AlertBulkRequest, request: Request) -> dict:
    _require_role(request, "security-operator", "admin")
    with get_session() as session:
        records = session.query(RemediationAlertDelivery).filter(RemediationAlertDelivery.id.in_(payload.delivery_ids), RemediationAlertDelivery.status.in_(["pending", "retrying"])).all()
        for record in records:
            record.status = "canceled"
            record.next_attempt_at = None
        return {"accepted": True, "canceled": [record.id for record in records], "skipped": sorted(set(payload.delivery_ids) - {record.id for record in records})}


@router.post("/remediations/recovery-bulk-status")
def bulk_recovery_status(payload: dict, request: Request) -> dict:
    _require_role(request, "security-operator", "admin")
    ids = payload.get("recovery_ids", [])
    status = payload.get("status")
    reason_code = payload.get("reason_code", "operator_reviewed")
    note = str(payload.get("note", ""))
    if not isinstance(ids, list) or not ids or len(ids) > 100 or status not in {"acknowledged", "failed"} or (status == "failed" and not note.strip()):
        raise HTTPException(status_code=400, detail="invalid_bulk_recovery_request")
    with get_session() as session:
        records = session.query(RemediationRecoveryRequest).filter(RemediationRecoveryRequest.id.in_(ids), RemediationRecoveryRequest.status.in_(["requested", "acknowledged"])).all()
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        for recovery in records:
            recovery.status = status
            recovery.note = note or recovery.note
            recovery.error_message = note if status == "failed" else None
            if status == "acknowledged": recovery.acknowledged_at = now
            else: recovery.completed_at = now
        return {"accepted": True, "updated": [record.id for record in records], "reason_code": reason_code, "skipped": sorted(set(ids) - {record.id for record in records})}


@router.post("/webhooks/{provider}")
async def provider_webhook(provider: str, request: Request) -> dict:
    provider = provider.lower()
    if provider not in {"github", "gitlab"}:
        raise HTTPException(status_code=404, detail="provider_not_supported")
    event_id = request.headers.get("x-provider-event-id", "") or request.headers.get("x-github-delivery", "") or request.headers.get("x-gitlab-event-uuid", "")
    signature = request.headers.get("x-provider-signature", "") or request.headers.get("x-hub-signature-256", "")
    secret = os.environ.get(f"{provider.upper()}_WEBHOOK_SECRET", "")
    body = await request.body()
    if not event_id or not verify_signature(provider=provider, body=body, signature=signature, secret=secret):
        record_provider_callback("rejected")
        raise HTTPException(status_code=401, detail="invalid_provider_signature")
    try:
        payload = json.loads(body.decode())
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="invalid_provider_payload") from exc
    try:
        callback = normalize_callback(provider=provider, payload=payload, event_id=event_id, event_type=request.headers.get("x-github-event") or request.headers.get("x-gitlab-event"))
    except (TypeError, ValueError, KeyError) as exc:
        raise HTTPException(status_code=400, detail="invalid_provider_payload") from exc
    with get_session() as session:
        if session.query(RemediationWebhookEvent).filter_by(provider=provider, event_id=event_id).first():
            record_provider_callback("duplicate")
            return {"accepted": True, "duplicate": True}
        publication = session.query(RemediationPublication).filter_by(provider=provider, repository=callback.repository, provider_number=callback.number).first()
        webhook = RemediationWebhookEvent(remediation_id=publication.remediation_id if publication else None, provider=provider, event_id=event_id, event_type=callback.event_type)
        session.add(webhook)
        if publication is None:
            record_provider_callback("unmatched")
            return {"accepted": True, "matched": False}
        publication.status = "merged" if callback.merged else callback.state
        publication.merged_at = datetime.now(timezone.utc).replace(tzinfo=None) if callback.merged else publication.merged_at
        publication.merge_commit = callback.merge_commit or publication.merge_commit
        publication.observed_digest = callback.observed_digest or publication.observed_digest
        publication.scan_status = callback.scan_status
        publication.findings_before = callback.findings_before
        publication.findings_after = callback.findings_after
        if callback.merged:
            result = evaluate_post_merge(
                expected_digest=callback.expected_digest,
                observed_digest=callback.observed_digest,
                required_scan_status=callback.scan_status,
                findings_before=callback.findings_before,
                findings_after=callback.findings_after,
            )
            _apply_post_merge_result(session, publication, result, callback.merge_commit)
            if result["status"] == "rollback_required":
                record_provider_callback("rollback_required")
        record_provider_callback("accepted")
        return {"accepted": True, "matched": True, "publication_id": publication.id, "verification_status": publication.verification_status}
