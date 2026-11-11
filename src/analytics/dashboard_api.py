"""Authenticated, read-only API used by the operations dashboard."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import uuid
import os

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator

from src.db.connection import get_session
from src.db.models import AuditEventType, AuditLog, Image, Remediation, RemediationActionType, RemediationStatus, Scan, ScanFinding, ScanStatus, Severity, SeveritySnapshot
from src.db.repositories import AuditLogRepository, RemediationRepository
from src.remediation.approval import approval_token_hash, issue_approval, verify_approval
from src.remediation.worker import execute_approved_remediation
from src.remediation.post_merge import evaluate_post_merge
from src.remediation.publication import build_publication_plan
from src.remediation.rollback import build_rollback_plan
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
    expected_digest: str
    observed_digest: str | None = None
    scan_status: str = Field(min_length=1, max_length=32)
    findings_before: int = Field(ge=0)
    findings_after: int = Field(ge=0)
    merge_commit: str | None = None


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
    return {
        "id": remediation.id,
        "image_id": remediation.image_id,
        "status": _value(remediation.status),
        "finding_count": remediation.finding_count,
        "target_severities": remediation.target_severities,
        "approved_by": remediation.approved_by,
        "approved_at": _iso(remediation.approved_at),
        "actions": actions if actions is not None else [{
            "id": action.id,
            "action_type": _value(action.action_type),
            "file_path": action.file_path,
            "before_value": action.before_value,
            "after_value": action.after_value,
            "success": action.success,
            "detail": action.detail,
        } for action in remediation.actions],
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


@router.get("/audit")
def dashboard_audit(
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    actor: str | None = Query(default=None, max_length=128),
    event_type: str | None = Query(default=None, max_length=64),
) -> dict:
    with get_session() as session:
        query = session.query(AuditLog)
        if actor:
            query = query.filter(AuditLog.actor == actor)
        if event_type:
            query = query.filter(AuditLog.event_type == event_type.lower())
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
