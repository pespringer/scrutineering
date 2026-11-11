"""Authenticated, read-only API used by the operations dashboard."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Query

from src.db.connection import get_session
from src.db.models import Image, Scan, ScanFinding, ScanStatus, Severity, SeveritySnapshot


router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


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
def scan_history(limit: int = Query(default=20, ge=1, le=100)) -> list[dict]:
    with get_session() as session:
        scans = session.query(Scan).order_by(Scan.started_at.desc()).limit(limit).all()
    return [_scan_payload(scan) for scan in scans]


@router.get("/images")
def image_inventory() -> list[dict]:
    with get_session() as session:
        images = session.query(Image).filter_by(active=True).all()
        findings = session.query(ScanFinding).filter_by(remediated=False).all()
    findings_by_image: dict[int, list[ScanFinding]] = defaultdict(list)
    for finding in findings:
        findings_by_image[finding.image_id].append(finding)
    return [_image_payload(image, findings_by_image[image.id]) for image in images]


@router.get("/images/{image_id}")
def image_detail(image_id: int, severity: str | None = Query(default=None)) -> dict:
    with get_session() as session:
        image = session.get(Image, image_id)
        if image is None:
            raise HTTPException(status_code=404, detail="image_not_found")
        findings = session.query(ScanFinding).filter_by(image_id=image_id, remediated=False).all()

    if severity and severity.lower() != "all":
        normalized = severity.lower()
        findings = [finding for finding in findings if _value(finding.severity) == normalized]
    return {"image": _image_payload(image, findings), "findings": [_finding_payload(finding) for finding in findings]}
