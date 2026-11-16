"""Scan history, scan controls, and the findings each scan observed."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query, Request

from src.db.connection import get_session
from src.db.models import (
    AuditEventType,
    FindingObservation,
    Image,
    Scan,
    ScanFinding,
    ScanStatus,
)
from src.scan.health import summarize_scan_health
from src.scan.records import queue_scan
from src.scan.tasks import app as celery_app
from src.api.schemas import BulkIdsRequest, ScanRequest
from src.api.serializers import (
    observation_payload,
    paginate,
    scan_payload,
)
from src.api.routes._access import record_operator_event, require_role, severity_filter

router = APIRouter()


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
    return paginate([scan_payload(scan) for scan in scans], limit, offset, total)


@router.get("/scans/health")
def scan_health(limit: int = Query(default=100, ge=1, le=1000)) -> dict:
    with get_session() as session:
        records = session.query(Scan).order_by(Scan.started_at.desc()).limit(limit).all()
    return summarize_scan_health([scan_payload(scan) for scan in records])


@router.post("/scans/{scan_id}/cancel")
def cancel_scan(scan_id: str, request: Request) -> dict:
    require_role(request, "operator", "security-operator")
    with get_session() as session:
        scan = session.query(Scan).filter_by(scan_id=scan_id).first()
        if scan is None:
            raise HTTPException(status_code=404, detail="scan_not_found")
        if scan.status in {ScanStatus.COMPLETED, ScanStatus.PARTIAL, ScanStatus.FAILED, ScanStatus.CANCELLED}:
            return scan_payload(scan)
        scan.status = ScanStatus.CANCELLED.value
        scan.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
        record_operator_event(session, request, AuditEventType.SCAN_CANCELLED, scan_id, {"action": "cancel_scan"})
    celery_app.control.revoke(scan_id, terminate=False)
    return {"scan_id": scan_id, "status": "cancelled"}


@router.post("/scans/bulk-cancel")
def bulk_cancel_scans(payload: BulkIdsRequest, request: Request) -> dict:
    require_role(request, "operator", "security-operator")
    scan_ids = [str(value) for value in payload.ids]
    changed: list[str] = []
    with get_session() as session:
        scans = session.query(Scan).filter(Scan.scan_id.in_(scan_ids)).all()
        for scan in scans:
            if scan.status in {ScanStatus.PENDING, ScanStatus.RUNNING}:
                scan.status = ScanStatus.CANCELLED.value
                scan.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
                changed.append(scan.scan_id)
                record_operator_event(
                    session, request, AuditEventType.SCAN_CANCELLED, scan.scan_id, {"action": "bulk_cancel_scan"}
                )
    for scan_id in changed:
        celery_app.control.revoke(scan_id, terminate=False)
    return {"requested": scan_ids, "cancelled": changed, "count": len(changed)}


@router.post("/scans/bulk-archive")
def bulk_archive_scans(payload: BulkIdsRequest, request: Request) -> dict:
    require_role(request, "operator", "security-operator")
    scan_ids = [str(value) for value in payload.ids]
    archived: list[str] = []
    with get_session() as session:
        for scan in (
            session.query(Scan)
            .filter(Scan.scan_id.in_(scan_ids), Scan.status.notin_([ScanStatus.PENDING, ScanStatus.RUNNING]))
            .all()
        ):
            scan.archived = True
            archived.append(scan.scan_id)
            record_operator_event(
                session, request, AuditEventType.CONFIG_CHANGED, scan.scan_id, {"action": "archive_scan"}
            )
    return {"requested": scan_ids, "archived": archived, "count": len(archived)}


@router.post("/scans/bulk-retry", status_code=202)
def bulk_retry_scans(payload: BulkIdsRequest, request: Request) -> dict:
    require_role(request, "operator", "security-operator")
    with get_session() as session:
        sources = [
            (scan.scan_id, scan.target or scan.image.full_name)
            for scan in session.query(Scan)
            .join(Image)
            .filter(
                Scan.scan_id.in_([str(value) for value in payload.ids]),
                Scan.status.in_([ScanStatus.FAILED, ScanStatus.CANCELLED]),
            )
            .all()
        ]
    retried: list[dict] = []
    for source_scan_id, target in sources:
        try:
            retry_id = queue_scan(target, priority="normal", trigger="retry")
        except Exception:
            continue
        with get_session() as session:
            record_operator_event(
                session,
                request,
                AuditEventType.SCAN_STARTED,
                retry_id,
                {"action": "retry_scan", "source_scan_id": source_scan_id},
            )
        retried.append({"source_scan_id": source_scan_id, "scan_id": retry_id, "image_name": target})
    return {"requested": payload.ids, "retried": retried, "count": len(retried)}


@router.get("/scans/{scan_id}")
def scan_status(scan_id: str) -> dict:
    with get_session() as session:
        scan = session.query(Scan).filter_by(scan_id=scan_id).first()
        if scan is None:
            raise HTTPException(status_code=404, detail="scan_not_found")
        return scan_payload(scan)


@router.get("/scans/{scan_id}/findings")
def scan_findings(
    scan_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    severity: str | None = Query(default=None),
    fixable_only: bool = Query(default=False),
) -> dict:
    """Return the persisted findings produced by one live scan."""
    severity_value = severity_filter(severity)
    with get_session() as session:
        scan = session.query(Scan).filter_by(scan_id=scan_id).first()
        if scan is None:
            raise HTTPException(status_code=404, detail="scan_not_found")
        query = (
            session.query(FindingObservation, ScanFinding)
            .join(ScanFinding, FindingObservation.finding_id == ScanFinding.id)
            .filter(FindingObservation.scan_id == scan_id)
        )
        if severity_value:
            query = query.filter(FindingObservation.severity == severity_value.value)
        if fixable_only:
            query = query.filter(FindingObservation.fixed_version.is_not(None), ScanFinding.resolved_at.is_(None))
        total = query.order_by(None).count()
        rows = query.order_by(FindingObservation.severity.asc(), ScanFinding.id.asc()).offset(offset).limit(limit).all()
        items = [observation_payload(observation, finding) for observation, finding in rows]
    return {"scan_id": scan_id, "image_id": scan.image_id, **paginate(items, limit, offset, total)}


@router.post("/scans", status_code=202)
def start_scan(payload: ScanRequest, request: Request) -> dict:
    require_role(request, "operator", "security-operator")
    try:
        scan_id = queue_scan(payload.image_name, priority=payload.priority, trigger="manual")
    except Exception as exc:
        raise HTTPException(status_code=503, detail="scan_queue_unavailable") from exc
    with get_session() as session:
        record_operator_event(
            session,
            request,
            AuditEventType.SCAN_STARTED,
            scan_id,
            {
                "action": "start_scan",
                "image_name": payload.image_name,
                "priority": payload.priority,
            },
        )
    return {"scan_id": scan_id, "task_id": scan_id, "image_name": payload.image_name, "status": "pending"}
