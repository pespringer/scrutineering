"""Posture summary and severity trend."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Query

from src.db.connection import get_session
from src.db.models import (
    Image,
    Scan,
    ScanFinding,
    ScanStatus,
    SeveritySnapshot,
)
from src.api.serializers import (
    enum_value,
    iso,
    severity_counts,
)

router = APIRouter()


@router.get("/posture/summary")
def posture_summary() -> dict:
    with get_session() as session:
        images = session.query(Image).filter_by(active=True).all()
        findings = session.query(ScanFinding).filter(ScanFinding.resolved_at.is_(None)).all()
        latest_scan = session.query(Scan).order_by(Scan.started_at.desc()).first()

    counts = severity_counts(findings)
    return {
        "total_scanned_images": len(images),
        "total_findings": len(findings),
        "critical_count": counts["critical"],
        "high_count": counts["high"],
        "medium_count": counts["medium"],
        "low_count": counts["low"],
        "fixable_count": sum(1 for finding in findings if finding.fix_available),
        "last_scan_at": iso(
            latest_scan.completed_at
            if latest_scan and latest_scan.completed_at
            else latest_scan.started_at
            if latest_scan
            else None
        ),
        "last_scan_status": enum_value(latest_scan.status) if latest_scan else None,
    }


@router.get("/posture/trend")
def posture_trend(days: int = Query(default=30, ge=1, le=365)) -> list[dict]:
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days)
    with get_session() as session:
        snapshots = session.query(SeveritySnapshot).filter(SeveritySnapshot.snapshot_date >= cutoff).all()
        if not snapshots:
            scans = (
                session.query(Scan)
                .filter(
                    Scan.status.in_([ScanStatus.COMPLETED, ScanStatus.PARTIAL]),
                    Scan.completed_at >= cutoff,
                )
                .order_by(Scan.completed_at)
                .all()
            )
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
