"""Authenticated, read-only API used by the operations dashboard."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import hashlib
import json
from urllib.parse import quote
from urllib.request import Request as UrlRequest, urlopen
import os

from fastapi import APIRouter, HTTPException, Query, Request
from sqlalchemy import func
from pydantic import BaseModel, Field, field_validator

from src.db.connection import get_session
from src.db.models import AuditEventType, AuditLog, FindingObservation, Image, Remediation, RemediationActionType, RemediationPublication, RemediationStatus, RemediationWebhookEvent, Scan, ScanFinding, ScanStatus, Severity, SeveritySnapshot
from src.db.repositories import AuditLogRepository, RemediationRepository
from src.remediation.worker import execute_approved_remediation
from src.remediation.post_merge import evaluate_post_merge
from src.remediation.events import publication_event_exists
from src.remediation.rollback import build_rollback_plan
from src.remediation.provider_callbacks import normalize_callback, verify_signature
from src.remediation.post_merge_tasks import queue_post_merge_scan, verify_post_merge_scan
from src.telemetry.scan_metrics import record_provider_callback
from src.scan.health import summarize_scan_health
from src.scan.image_identity import parse_image_reference
from src.scan.records import queue_scan
from src.scan.tasks import app as celery_app


router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


class ScanRequest(BaseModel):
    image_name: str = Field(min_length=1, max_length=512)
    priority: str = Field(default="normal", pattern="^(low|normal|high)$")

    @field_validator("image_name")
    @classmethod
    def image_name_must_be_an_image_reference(cls, value: str) -> str:
        value = value.strip()
        if not value or any(char.isspace() for char in value):
            raise ValueError("image_name must be a single image reference")
        if value.startswith("fs:"):
            # Filesystem scans are an internal remediation tool, not a public scan target.
            raise ValueError("image_name must be a container image reference")
        parse_image_reference(value)
        return value


class BulkIdsRequest(BaseModel):
    ids: list[int | str] = Field(min_length=1, max_length=100)


class BulkFindingAssignmentRequest(BaseModel):
    finding_ids: list[int] = Field(min_length=1, max_length=100)
    assignee: str | None = Field(default=None, max_length=128)

    @field_validator("assignee")
    @classmethod
    def assignee_is_safe(cls, value: str | None) -> str | None:
        if value is not None and any(char.isspace() for char in value.strip()):
            raise ValueError("assignee must not contain whitespace")
        return value.strip() if value else None


class RemediationRequest(BaseModel):
    image_id: int = Field(gt=0)
    finding_ids: list[int] = Field(min_length=1, max_length=50)


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
        "image_id": getattr(scan, "image_id", None),
        "image_name": getattr(scan, "target", None) or (scan.image.full_name if scan.image else "unknown"),
        "target": getattr(scan, "target", None),
        "status": _value(scan.status),
        "phase": getattr(scan, "phase", None) or _value(scan.status),
        "task_id": getattr(scan, "task_id", None),
        "started_at": _iso(scan.started_at),
        "completed_at": _iso(scan.completed_at),
        "findings": scan.total_findings or 0,
        "critical_count": scan.critical_count or 0,
        "high_count": scan.high_count or 0,
        "medium_count": scan.medium_count or 0,
        "low_count": scan.low_count or 0,
        "archived": bool(getattr(scan, "archived", False)),
        "scanner_versions": getattr(scan, "scanner_versions", None) or {},
        "vulnerability_db_versions": getattr(scan, "vulnerability_db_versions", None) or {},
        "error_message": getattr(scan, "error_message", None),
    }


def _image_payload(image: Image, findings: list[ScanFinding], resolved_count: int = 0) -> dict:
    counts = _severity_counts(findings)
    return {
        "id": image.id,
        "registry": _value(image.registry_name),
        "name": image.full_name,
        "repo_name": image.repo_name,
        "tag": image.tag,
        "last_scan_at": _iso(image.last_scan_at),
        "last_scan_id": image.last_scan_id,
        "open_findings": len(findings),
        "resolved_findings": resolved_count,
        "critical_count": counts["critical"],
        "high_count": counts["high"],
        "medium_count": counts["medium"],
        "low_count": counts["low"],
    }


def _local_registry_base_url() -> str:
    configured = os.environ.get("LOCAL_REGISTRY_URL", "").strip()
    if configured:
        return configured.rstrip("/")
    host = os.environ.get("LOCAL_REGISTRY_HOST", "registry:5000").strip()
    scheme = "http" if os.environ.get("REGISTRY_INSECURE", "true").lower() in {"1", "true", "yes"} else "https"
    return f"{scheme}://{host}"


def _local_registry_public_url() -> str:
    configured = os.environ.get("LOCAL_REGISTRY_PUBLIC_URL", "").strip()
    if configured:
        return configured.rstrip("/")
    host = os.environ.get("LOCAL_REGISTRY_PUBLIC_HOST", "localhost:5000").strip()
    scheme = "http" if os.environ.get("REGISTRY_INSECURE", "true").lower() in {"1", "true", "yes"} else "https"
    return f"{scheme}://{host}"


def _registry_json(path: str) -> dict:
    request = UrlRequest(f"{_local_registry_base_url()}{path}", headers={"accept": "application/json"})
    with urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def _registry_manifest_metadata(repository: str, tag: str) -> dict:
    path = f"/v2/{quote(repository, safe='/')}/manifests/{quote(tag, safe='')}"
    request = UrlRequest(f"{_local_registry_base_url()}{path}", headers={
        "accept": ", ".join([
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.v2+json",
            "application/vnd.docker.distribution.manifest.list.v2+json",
        ])
    }, method="HEAD")
    with urlopen(request, timeout=10) as response:
        return {"digest": response.headers.get("Docker-Content-Digest"), "size": int(response.headers.get("Content-Length") or 0)}


def _finding_payload(finding: ScanFinding) -> dict:
    severity = _value(finding.severity)
    return {
        "id": finding.id,
        "fingerprint": finding.fingerprint,
        "cve_id": finding.cve_id,
        "package_name": finding.package_name,
        "package_version": finding.package_version,
        "package_type": finding.package_type,
        "file_path": getattr(finding, "file_path", None),
        "severity": severity.upper() if severity else "UNKNOWN",
        "title": finding.title,
        "description": finding.description,
        "fixed_version": finding.fixed_version,
        "fix_available": bool(finding.fix_available),
        "first_seen": _iso(finding.first_seen),
        "last_seen": _iso(finding.last_seen),
        "resolved_at": _iso(getattr(finding, "resolved_at", None)),
        "reopened_at": _iso(getattr(finding, "reopened_at", None)),
        "lifecycle_status": "resolved" if getattr(finding, "resolved_at", None) else "open",
        "acknowledged": bool(getattr(finding, "acknowledged", False)),
        "assigned_to": getattr(finding, "assigned_to", None),
        "remediation_id": getattr(finding, "remediation_id", None),
    }


def _observation_payload(observation: FindingObservation, finding: ScanFinding) -> dict:
    """A finding as one scan saw it; lifecycle fields reflect its current state."""
    severity = _value(observation.severity)
    return {
        **_finding_payload(finding),
        "severity": severity.upper() if severity else "UNKNOWN",
        "fixed_version": observation.fixed_version,
        "fix_available": observation.fixed_version is not None,
        "file_path": observation.file_path,
        "observed_at": _iso(observation.observed_at),
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


def _remediation_file_path(finding: ScanFinding, image: Image | None = None) -> str | None:
    file_path = getattr(finding, "file_path", None)
    if not file_path or image is None:
        return file_path
    repository_name = str(getattr(image, "repo_name", ""))
    if getattr(image, "tag", None) == "filesystem" and repository_name.startswith("local/"):
        source_directory = repository_name.removeprefix("local/")
        if source_directory and not file_path.startswith(f"{source_directory}/"):
            return f"{source_directory}/{file_path}"
    return file_path


def _remediation_actions(findings: list[ScanFinding], image: Image | None = None) -> list[dict]:
    return [{
        "finding_id": finding.id,
        "action_type": RemediationActionType.DEPENDENCY_UPDATE.value,
        "package_name": finding.package_name,
        "from_version": finding.package_version,
        "to_version": finding.fixed_version,
        "file_path": _remediation_file_path(finding, image),
        "cve_id": finding.cve_id,
        "severity": _value(finding.severity),
        "safe_to_apply": bool(finding.fix_available and finding.fixed_version and _remediation_file_path(finding, image)),
    } for finding in findings]


def _unsafe_remediation_actions(actions: list[dict]) -> list[dict]:
    return [action for action in actions if not action["safe_to_apply"]]


def _remediation_payload(remediation: Remediation, actions: list[dict] | None = None) -> dict:
    remediation_findings = list(getattr(remediation, "findings", []) or [])
    resolved_findings = sum(1 for finding in remediation_findings if getattr(finding, "resolved_at", None) is not None)
    remediation_events = list(getattr(remediation, "events", []) or [])
    latest_event = remediation_events[-1] if remediation_events else None
    workflow_state = _remediation_workflow_state(remediation, remediation_events)
    workflow_label = {"execution_queued": "Queued for execution", "execution_started": "Execution in progress", "execution_ready": "Execution ready", "execution_blocked": "Execution blocked", "requires_review": "Awaiting approval", "analyzing": "Awaiting execution", "completed": "Completed", "failed": "Failed"}.get(workflow_state, workflow_state.replace("_", " ").title())
    return {
        "id": remediation.id,
        "image_id": remediation.image_id,
        "status": _value(remediation.status),
        "workflow_state": workflow_state,
        "workflow_label": workflow_label,
        "latest_event_type": latest_event.event_type if latest_event else None,
        "finding_count": remediation.finding_count,
        "open_finding_count": max(len(remediation_findings) - resolved_findings, 0),
        "resolved_finding_count": resolved_findings,
        "resolution_status": "resolved" if remediation_findings and resolved_findings == len(remediation_findings) else "open",
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
        "publications": [{
            "id": publication.id, "provider": publication.provider,
            "repository": publication.repository, "status": publication.status,
            "url": publication.url, "number": publication.provider_number,
            "merged_at": _iso(publication.merged_at),
            "verification_status": publication.verification_status,
            "scan_status": publication.scan_status,
            "post_merge_scan_id": publication.post_merge_scan_id,
            "verification_detail": publication.verification_detail,
            "findings_before": publication.findings_before,
            "findings_after": publication.findings_after,
            "rollback_command": publication.rollback_command,
        } for publication in remediation.publications],
    }


def _remediation_workflow_state(remediation: Remediation, events: list | None = None) -> str:
    """Return the operator-facing state, including asynchronous execution progress."""
    status = _value(remediation.status)
    if status == RemediationStatus.REQUIRES_REVIEW.value:
        return status
    execution_events = {"execution_queued", "execution_started", "execution_ready", "execution_blocked", "execution_retry_requested"}
    for event in reversed(events if events is not None else list(getattr(remediation, "events", []) or [])):
        if event.event_type == "execution_retry_requested":
            # A retry returns the record to review; once re-approved the status
            # column is authoritative until a new execution event arrives.
            return status
        if event.event_type in execution_events:
            return event.event_type
    return status


@router.get("/posture/summary")
def posture_summary() -> dict:
    with get_session() as session:
        images = session.query(Image).filter_by(active=True).all()
        findings = session.query(ScanFinding).filter(ScanFinding.resolved_at.is_(None)).all()
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
        if not snapshots:
            scans = session.query(Scan).filter(
                Scan.status.in_([ScanStatus.COMPLETED, ScanStatus.PARTIAL]),
                Scan.completed_at >= cutoff,
            ).order_by(Scan.completed_at).all()
            grouped = defaultdict(lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0})
            for scan in scans:
                if scan.completed_at:
                    day = scan.completed_at.date().isoformat()
                    grouped[day]["critical"] = max(grouped[day]["critical"], scan.critical_count or 0)
                    grouped[day]["high"] = max(grouped[day]["high"], scan.high_count or 0)
                    grouped[day]["medium"] = max(grouped[day]["medium"], scan.medium_count or 0)
                    grouped[day]["low"] = max(grouped[day]["low"], scan.low_count or 0)
            return [{"date": day, **grouped[day]} for day in sorted(grouped)]

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
    include_archived: bool = Query(default=False),
) -> dict:
    with get_session() as session:
        query = session.query(Scan).join(Image)
        if not include_archived:
            query = query.filter(Scan.archived.is_(False))
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


@router.get("/scans/health")
def scan_health(limit: int = Query(default=100, ge=1, le=1000)) -> dict:
    with get_session() as session:
        records = session.query(Scan).order_by(Scan.started_at.desc()).limit(limit).all()
    return summarize_scan_health([_scan_payload(scan) for scan in records])


@router.post("/scans/{scan_id}/cancel")
def cancel_scan(scan_id: str, request: Request) -> dict:
    _require_role(request, "operator", "security-operator")
    with get_session() as session:
        scan = session.query(Scan).filter_by(scan_id=scan_id).first()
        if scan is None:
            raise HTTPException(status_code=404, detail="scan_not_found")
        if scan.status in {ScanStatus.COMPLETED, ScanStatus.PARTIAL, ScanStatus.FAILED, ScanStatus.CANCELLED}:
            return _scan_payload(scan)
        scan.status = ScanStatus.CANCELLED.value
        scan.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
        _record_operator_event(session, request, AuditEventType.SCAN_CANCELLED, scan_id, {"action": "cancel_scan"})
    celery_app.control.revoke(scan_id, terminate=False)
    return {"scan_id": scan_id, "status": "cancelled"}


@router.post("/scans/bulk-cancel")
def bulk_cancel_scans(payload: BulkIdsRequest, request: Request) -> dict:
    _require_role(request, "operator", "security-operator")
    scan_ids = [str(value) for value in payload.ids]
    changed: list[str] = []
    with get_session() as session:
        scans = session.query(Scan).filter(Scan.scan_id.in_(scan_ids)).all()
        for scan in scans:
            if scan.status in {ScanStatus.PENDING, ScanStatus.RUNNING}:
                scan.status = ScanStatus.CANCELLED.value
                scan.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
                changed.append(scan.scan_id)
                _record_operator_event(session, request, AuditEventType.SCAN_CANCELLED, scan.scan_id, {"action": "bulk_cancel_scan"})
    for scan_id in changed:
        celery_app.control.revoke(scan_id, terminate=False)
    return {"requested": scan_ids, "cancelled": changed, "count": len(changed)}


@router.post("/scans/bulk-archive")
def bulk_archive_scans(payload: BulkIdsRequest, request: Request) -> dict:
    _require_role(request, "operator", "security-operator")
    scan_ids = [str(value) for value in payload.ids]
    archived: list[str] = []
    with get_session() as session:
        for scan in session.query(Scan).filter(Scan.scan_id.in_(scan_ids), Scan.status.notin_([ScanStatus.PENDING, ScanStatus.RUNNING])).all():
            scan.archived = True
            archived.append(scan.scan_id)
            _record_operator_event(session, request, AuditEventType.CONFIG_CHANGED, scan.scan_id, {"action": "archive_scan"})
    return {"requested": scan_ids, "archived": archived, "count": len(archived)}


@router.post("/scans/bulk-retry", status_code=202)
def bulk_retry_scans(payload: BulkIdsRequest, request: Request) -> dict:
    _require_role(request, "operator", "security-operator")
    with get_session() as session:
        sources = [
            (scan.scan_id, scan.target or scan.image.full_name)
            for scan in session.query(Scan).join(Image).filter(
                Scan.scan_id.in_([str(value) for value in payload.ids]),
                Scan.status.in_([ScanStatus.FAILED, ScanStatus.CANCELLED]),
            ).all()
        ]
    retried: list[dict] = []
    for source_scan_id, target in sources:
        try:
            retry_id = queue_scan(target, priority="normal", trigger="retry")
        except Exception:
            continue
        with get_session() as session:
            _record_operator_event(session, request, AuditEventType.SCAN_STARTED, retry_id,
                                   {"action": "retry_scan", "source_scan_id": source_scan_id})
        retried.append({"source_scan_id": source_scan_id, "scan_id": retry_id, "image_name": target})
    return {"requested": payload.ids, "retried": retried, "count": len(retried)}


@router.get("/scans/{scan_id}")
def scan_status(scan_id: str) -> dict:
    with get_session() as session:
        scan = session.query(Scan).filter_by(scan_id=scan_id).first()
        if scan is None:
            raise HTTPException(status_code=404, detail="scan_not_found")
        return _scan_payload(scan)


@router.get("/scans/{scan_id}/findings")
def scan_findings(
    scan_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    severity: str | None = Query(default=None),
    fixable_only: bool = Query(default=False),
) -> dict:
    """Return the persisted findings produced by one live scan."""
    severity_value = _severity_filter(severity)
    with get_session() as session:
        scan = session.query(Scan).filter_by(scan_id=scan_id).first()
        if scan is None:
            raise HTTPException(status_code=404, detail="scan_not_found")
        query = (session.query(FindingObservation, ScanFinding)
                 .join(ScanFinding, FindingObservation.finding_id == ScanFinding.id)
                 .filter(FindingObservation.scan_id == scan_id))
        if severity_value:
            query = query.filter(FindingObservation.severity == severity_value.value)
        if fixable_only:
            query = query.filter(FindingObservation.fixed_version.is_not(None), ScanFinding.resolved_at.is_(None))
        total = query.order_by(None).count()
        rows = (query.order_by(FindingObservation.severity.asc(), ScanFinding.id.asc())
                .offset(offset).limit(limit).all())
        items = [_observation_payload(observation, finding) for observation, finding in rows]
    return {"scan_id": scan_id, "image_id": scan.image_id, **_page(items, limit, offset, total)}


@router.post("/scans", status_code=202)
def start_scan(payload: ScanRequest, request: Request) -> dict:
    _require_role(request, "operator", "security-operator")
    try:
        scan_id = queue_scan(payload.image_name, priority=payload.priority, trigger="manual")
    except Exception as exc:
        raise HTTPException(status_code=503, detail="scan_queue_unavailable") from exc
    with get_session() as session:
        _record_operator_event(session, request, AuditEventType.SCAN_STARTED, scan_id, {
            "action": "start_scan", "image_name": payload.image_name, "priority": payload.priority,
        })
    return {"scan_id": scan_id, "task_id": scan_id, "image_name": payload.image_name, "status": "pending"}


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
            query = query.filter(Image.id.in_(session.query(ScanFinding.image_id).filter(ScanFinding.resolved_at.is_(None), ScanFinding.severity == severity_value.value)))
        total = query.order_by(None).count()
        images = query.order_by(Image.repo_name.asc()).offset(offset).limit(limit).all()
        image_ids = [image.id for image in images]
        findings = session.query(ScanFinding).filter(
            ScanFinding.image_id.in_(image_ids), ScanFinding.resolved_at.is_(None),
        ).all() if image_ids else []
        resolved_counts = dict(session.query(ScanFinding.image_id, func.count(ScanFinding.id)).filter(
            ScanFinding.image_id.in_(image_ids), ScanFinding.resolved_at.is_not(None),
        ).group_by(ScanFinding.image_id).all()) if image_ids else {}
    findings_by_image: dict[int, list[ScanFinding]] = defaultdict(list)
    for finding in findings:
        findings_by_image[finding.image_id].append(finding)
    return _page([_image_payload(image, findings_by_image[image.id], resolved_counts.get(image.id, 0)) for image in images], limit, offset, total)


@router.get("/registry/inventory")
def registry_inventory(request: Request) -> dict:
    """Return the local registry catalog joined with scan and finding state."""
    _require_role(request, "dashboard", "operator", "security-operator")
    try:
        catalog = _registry_json("/v2/_catalog?n=1000")
        repositories = [str(value) for value in catalog.get("repositories", [])]
        catalog_items: list[dict] = []
        for repository in repositories:
            tags_payload = _registry_json(f"/v2/{quote(repository, safe='/')}/tags/list")
            for tag in sorted(tags_payload.get("tags") or []):
                try:
                    manifest = _registry_manifest_metadata(repository, str(tag))
                except Exception as exc:
                    manifest = {"digest": None, "size": 0, "error": str(exc)[:200]}
                catalog_items.append({"repository": repository, "tag": str(tag), **manifest})
    except Exception as exc:
        raise HTTPException(status_code=503, detail="local_registry_unavailable") from exc

    registry_host = os.environ.get("LOCAL_REGISTRY_HOST", "registry:5000").strip()
    with get_session() as session:
        images = session.query(Image).filter(Image.active.is_(True)).all()
        image_ids = [image.id for image in images]
        scans = session.query(Scan).filter(Scan.image_id.in_(image_ids)).order_by(Scan.started_at.desc(), Scan.id.desc()).all() if image_ids else []
        findings = session.query(ScanFinding).filter(ScanFinding.image_id.in_(image_ids)).all() if image_ids else []

    scans_by_image: dict[int, Scan] = {}
    for scan in scans:
        scans_by_image.setdefault(scan.image_id, scan)
    findings_by_image: dict[int, list[ScanFinding]] = defaultdict(list)
    for finding in findings:
        findings_by_image[finding.image_id].append(finding)
    image_lookup: dict[tuple[str, str], Image] = {}
    for image in images:
        image_lookup[(f"{registry_host}/{image.repo_name}", image.tag)] = image
        image_lookup[(image.repo_name, image.tag)] = image

    tags: list[dict] = []
    for item in catalog_items:
        image = image_lookup.get((f"{registry_host}/{item['repository']}", item["tag"])) or image_lookup.get((item["repository"], item["tag"]))
        image_findings = [finding for finding in findings_by_image.get(image.id, []) if finding.resolved_at is None] if image else []
        scan = scans_by_image.get(image.id) if image else None
        scan_status = _value(scan.status) if scan else None
        if scan_status in {"pending", "running"}:
            security_status = "scanning"
        elif scan_status == "failed":
            security_status = "scan_failed"
        elif scan is None:
            security_status = "not_scanned"
        elif image_findings:
            security_status = "issues_found"
        else:
            security_status = "clean"
        tags.append({
            **item,
            "image_id": image.id if image else None,
            "scan_id": scan.scan_id if scan else None,
            "scan_status": scan_status,
            "last_scan_at": _iso(image.last_scan_at) if image else None,
            "security_status": security_status,
            "open_findings": len(image_findings),
            "critical_count": sum(1 for finding in image_findings if _value(finding.severity) == "critical"),
            "high_count": sum(1 for finding in image_findings if _value(finding.severity) == "high"),
            "image_name": f"{registry_host}/{item['repository']}:{item['tag']}",
        })

    counts = Counter(item["security_status"] for item in tags)
    return {
        "registry": {"host": os.environ.get("LOCAL_REGISTRY_PUBLIC_HOST", "localhost:5000"), "url": _local_registry_public_url(), "internal_host": registry_host, "reachable": True},
        "repositories": repositories,
        "tags": tags,
        "summary": {
            "repositories": len(repositories),
            "tags": len(tags),
            "scanned": len(tags) - counts.get("not_scanned", 0),
            "not_scanned": counts.get("not_scanned", 0),
            "scanning": counts.get("scanning", 0),
            "issues_found": counts.get("issues_found", 0),
            "clean": counts.get("clean", 0),
        },
    }


@router.post("/images/bulk-archive")
def bulk_archive_images(payload: BulkIdsRequest, request: Request) -> dict:
    _require_role(request, "operator", "security-operator")
    image_ids = [int(value) for value in payload.ids]
    archived: list[int] = []
    with get_session() as session:
        for image in session.query(Image).filter(Image.id.in_(image_ids), Image.active.is_(True)).all():
            image.active = False
            archived.append(image.id)
            _record_operator_event(session, request, AuditEventType.CONFIG_CHANGED, str(image.id), {"action": "archive_image"}, entity_type="image")
    return {"requested": image_ids, "archived": archived, "count": len(archived)}


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
        query = session.query(ScanFinding).filter(ScanFinding.image_id == image_id, ScanFinding.resolved_at.is_(None))
        if severity_value:
            query = query.filter(ScanFinding.severity == severity_value.value)
        total = query.order_by(None).count()
        findings = query.order_by(ScanFinding.severity.asc(), ScanFinding.id.asc()).offset(offset).limit(limit).all()
        all_findings = session.query(ScanFinding).filter(ScanFinding.image_id == image_id, ScanFinding.resolved_at.is_(None)).all()
        resolved_count = session.query(ScanFinding).filter(ScanFinding.image_id == image_id, ScanFinding.resolved_at.is_not(None)).count()
    return {
        "image": _image_payload(image, all_findings, resolved_count),
        "findings": [_finding_payload(finding) for finding in findings],
        "findings_page": _page([_finding_payload(finding) for finding in findings], limit, offset, total),
    }


@router.post("/findings/bulk-acknowledge")
def bulk_acknowledge_findings(payload: BulkIdsRequest, request: Request) -> dict:
    _require_role(request, "operator", "security-operator")
    finding_ids = [int(value) for value in payload.ids]
    changed: list[int] = []
    with get_session() as session:
        for finding in session.query(ScanFinding).filter(ScanFinding.id.in_(finding_ids), ScanFinding.resolved_at.is_(None)).all():
            finding.acknowledged = True
            changed.append(finding.id)
        if changed:
            _record_operator_event(session, request, AuditEventType.CONFIG_CHANGED, ",".join(map(str, changed)), {"action": "acknowledge_findings", "finding_ids": changed}, entity_type="finding")
    return {"requested": finding_ids, "acknowledged": changed, "count": len(changed)}


@router.post("/findings/bulk-assign")
def bulk_assign_findings(payload: BulkFindingAssignmentRequest, request: Request) -> dict:
    _require_role(request, "operator", "security-operator")
    changed: list[int] = []
    with get_session() as session:
        for finding in session.query(ScanFinding).filter(ScanFinding.id.in_(payload.finding_ids), ScanFinding.resolved_at.is_(None)).all():
            finding.assigned_to = payload.assignee
            changed.append(finding.id)
        if changed:
            _record_operator_event(session, request, AuditEventType.CONFIG_CHANGED, ",".join(map(str, changed)), {"action": "assign_findings", "finding_ids": changed, "assignee": payload.assignee}, entity_type="finding")
    return {"requested": payload.finding_ids, "assigned": changed, "assignee": payload.assignee, "count": len(changed)}


@router.get("/findings/export")
def export_findings(request: Request, limit: int = Query(default=1000, ge=1, le=5000), severity: str | None = Query(default=None), image_id: int | None = Query(default=None), acknowledged: bool | None = Query(default=None)) -> dict:
    _require_role(request, "dashboard", "operator", "security-operator")
    severity_value = _severity_filter(severity)
    with get_session() as session:
        query = session.query(ScanFinding).filter(ScanFinding.resolved_at.is_(None))
        if severity_value: query = query.filter(ScanFinding.severity == severity_value.value)
        if image_id: query = query.filter(ScanFinding.image_id == image_id)
        if acknowledged is not None: query = query.filter(ScanFinding.acknowledged.is_(acknowledged))
        findings = query.order_by(ScanFinding.id.asc()).limit(limit).all()
    records = [_finding_payload(finding) for finding in findings]
    canonical = json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
    return {"format": "scrutineering-findings-v1", "count": len(records), "sha256": hashlib.sha256(canonical).hexdigest(), "records": records}


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
            ScanFinding.resolved_at.is_(None),
        ).order_by(ScanFinding.severity.asc(), ScanFinding.id.asc()).all()
    if image is None:
        raise HTTPException(status_code=404, detail="image_not_found")
    if len(findings) != len(set(payload.finding_ids)):
        raise HTTPException(status_code=400, detail="findings_must_belong_to_image")
    actions = _remediation_actions(findings, image)
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
    requested_ids = set(payload.finding_ids)
    if len(requested_ids) != len(payload.finding_ids):
        raise HTTPException(status_code=400, detail="finding_ids_must_be_unique")
    with get_session() as session:
        image = session.get(Image, payload.image_id)
        requested_findings = session.query(ScanFinding).filter(
            ScanFinding.image_id == payload.image_id,
            ScanFinding.id.in_(requested_ids),
        ).all()
        already_owned = {
            finding.id: finding.remediation_id
            for finding in requested_findings
            if finding.remediation_id is not None
        }
        if already_owned:
            raise HTTPException(status_code=409, detail={
                "code": "finding_already_in_remediation",
                "finding_ids": sorted(already_owned),
                "remediation_ids": sorted({value for value in already_owned.values() if value is not None}),
            })
        findings = session.query(ScanFinding).filter(
            ScanFinding.image_id == payload.image_id,
            ScanFinding.id.in_(requested_ids),
            ScanFinding.resolved_at.is_(None),
            ScanFinding.fix_available.is_(True),
        ).all()
        if image is None:
            raise HTTPException(status_code=404, detail="image_not_found")
        if len(findings) != len(set(payload.finding_ids)):
            raise HTTPException(status_code=400, detail="all_findings_need_available_fixes")
        actions = _remediation_actions(findings, image)
        unsafe_actions = _unsafe_remediation_actions(actions)
        if unsafe_actions:
            raise HTTPException(status_code=400, detail={
                "code": "findings_not_actionable",
                "finding_ids": [action["finding_id"] for action in unsafe_actions],
                "reason": "Each remediation action requires a fixed version and explicit source file path.",
            })
        severities = Counter(_value(finding.severity) or "unknown" for finding in findings)
        remediation = RemediationRepository.create(
            session,
            image_id=image.id,
            finding_count=len(findings),
            target_severities=dict(severities),
        )
        remediation.status = RemediationStatus.REQUIRES_REVIEW
        for finding, action in zip(findings, actions):
            finding.remediation_id = remediation.id
            RemediationRepository.add_action(
                session, remediation.id, RemediationActionType.DEPENDENCY_UPDATE,
                file_path=_remediation_file_path(finding, image),
                before_value=finding.package_version, after_value=finding.fixed_version,
                detail={"finding_id": finding.id, "package_name": finding.package_name, "cve_id": finding.cve_id, "file_path": _remediation_file_path(finding, image)},
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
    return {"remediation_id": remediation_id, "latest_event": ({
        "event_type": events[-1].event_type,
        "detail": events[-1].detail,
        "created_at": _iso(events[-1].created_at),
    } if events else None), "events": [{
        "id": event.id, "event_type": event.event_type, "sequence": event.sequence,
        "detail": event.detail, "created_at": _iso(event.created_at),
    } for event in events]}


@router.post("/remediations/{remediation_id}/approve")
def approve_remediation(remediation_id: int, request: Request) -> dict:
    """Approve a proposed remediation for execution. Requires the security-operator role."""
    _require_role(request, "security-operator")
    approver = getattr(request.state, "principal_id", "dashboard-service")
    with get_session() as session:
        remediation = session.get(Remediation, remediation_id)
        if remediation is None:
            raise HTTPException(status_code=404, detail="remediation_not_found")
        if _value(remediation.status) != RemediationStatus.REQUIRES_REVIEW.value:
            raise HTTPException(status_code=409, detail="remediation_not_awaiting_approval")
        RemediationRepository.update_status(
            session, remediation_id, RemediationStatus.ANALYZING,
            approved_by=approver, approved_at=datetime.now(timezone.utc).replace(tzinfo=None),
        )
        _record_operator_event(
            session, request, AuditEventType.CONFIG_CHANGED, str(remediation_id),
            {"action": "remediation_approved", "approver": approver}, entity_type="remediation",
        )
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
        events = RemediationRepository.list_events(session, remediation_id)
        if any(event.event_type == "execution_ready" for event in events):
            raise HTTPException(status_code=409, detail="remediation_execution_already_complete")
        if any(event.event_type in {"execution_queued", "execution_started"} for event in events):
            raise HTTPException(status_code=409, detail="remediation_execution_already_queued")
        if _value(remediation.status) != RemediationStatus.ANALYZING.value:
            raise HTTPException(status_code=409, detail="remediation_not_approved")
        RemediationRepository.append_event(session, {
            "remediation_id": remediation_id,
            "event_type": "execution_queued",
            "sequence": len(events) + 1,
            "detail": {"action": "execution_queued"},
        })
        task = execute_approved_remediation.apply_async(args=[remediation_id], queue="remediation.normal")
        _record_operator_event(session, request, AuditEventType.CONFIG_CHANGED, str(remediation_id), {"action": "remediation_execution_requested", "task_id": task.id}, entity_type="remediation")
    return {"remediation_id": remediation_id, "task_id": task.id, "status": "queued"}


@router.post("/remediations/{remediation_id}/retry")
def retry_remediation(remediation_id: int, request: Request) -> dict:
    """Return a failed execution to approval so an operator can deliberately restart it."""
    _require_role(request, "security-operator")
    with get_session() as session:
        remediation = session.get(Remediation, remediation_id)
        if remediation is None:
            raise HTTPException(status_code=404, detail="remediation_not_found")
        if _value(remediation.status) != RemediationStatus.FAILED.value:
            raise HTTPException(status_code=409, detail="remediation_not_failed")
        RemediationRepository.update_status(session, remediation_id, RemediationStatus.REQUIRES_REVIEW)
        remediation.error_message = None
        events = RemediationRepository.list_events(session, remediation_id)
        RemediationRepository.append_event(session, {
            "remediation_id": remediation_id,
            "event_type": "execution_retry_requested",
            "sequence": len(events) + 1,
            "detail": {"action": "execution_retry_requested"},
        })
        return _remediation_payload(RemediationRepository.get_by_id(session, remediation_id))


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
    verification_task_id = None
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
            if callback.expected_digest and callback.scan_status == "completed":
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
            else:
                scan_id = queue_post_merge_scan(session, publication)
                publication.verification_status = "pending"
                publication.verification_detail = {
                    "status": "pending",
                    "reason": "deployment_evidence_not_in_provider_callback",
                    "scan_id": scan_id,
                }
                events = RemediationRepository.list_events(session, publication.remediation_id)
                if not any(event.event_type == "post_merge_verification_queued" and event.detail.get("publication_id") == publication.id for event in events):
                    RemediationRepository.append_event(session, {
                        "remediation_id": publication.remediation_id,
                        "event_type": "post_merge_verification_queued",
                        "sequence": len(events) + 1,
                        "detail": {"publication_id": publication.id, "scan_id": scan_id, "reason": "deployment_evidence_not_in_provider_callback"},
                    })
                verification_task_id = verify_post_merge_scan.apply_async(args=[publication.id, scan_id], countdown=10).id
        record_provider_callback("accepted")
        return {"accepted": True, "matched": True, "publication_id": publication.id, "verification_status": publication.verification_status, "verification_task_id": verification_task_id}
