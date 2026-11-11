"""Authenticated, read-only API used by the operations dashboard."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

from src.db.connection import get_session
from src.db.models import Image, Scan, ScanFinding, ScanStatus, Severity, SeveritySnapshot
from src.scan.image_identity import parse_image_reference
from src.scan.tasks import enqueue_scan


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


@router.post("/scans", status_code=202)
def start_scan(request: ScanRequest) -> dict:
    scan_id = __import__("uuid").uuid4().hex
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    identity = parse_image_reference(request.image_name)
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
        task = enqueue_scan(request.image_name, priority=request.priority, scan_id=scan_id)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="scan_queue_unavailable") from exc
    return {"scan_id": scan_id, "task_id": task.id, "image_name": request.image_name, "status": "pending"}


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
