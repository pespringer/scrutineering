"""Trend analysis for Container Sentinel — historical severity tracking."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

from src.db.models import SeveritySnapshot, Image, ScanFinding, Scan


class TrendAnalyzer:
    """Analyzes historical trends from severity_snapshots and scan data."""

    def get_severity_trend(
        self, session: Session, image_id: int, days: int = 30
    ) -> list[dict[str, Any]]:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        snapshots = (
            session.query(SeveritySnapshot)
            .filter(
                SeveritySnapshot.image_id == image_id,
                SeveritySnapshot.snapshot_date >= cutoff,
            )
            .order_by(SeveritySnapshot.snapshot_date)
            .all()
        )
        return [
            {
                "date": s.snapshot_date.isoformat(),
                "critical": s.critical_count,
                "high": s.high_count,
                "medium": s.medium_count,
                "low": s.low_count,
                "total_open": s.total_open,
                "newly_fixed": s.newly_fixed,
            }
            for s in snapshots
        ]

    def get_overall_trend(
        self, session: Session, days: int = 30
    ) -> list[dict[str, Any]]:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        snapshots = (
            session.query(SeveritySnapshot)
            .filter(SeveritySnapshot.snapshot_date >= cutoff)
            .order_by(SeveritySnapshot.snapshot_date)
            .all()
        )
        aggregated: dict[str, dict] = {}
        for s in snapshots:
            key = s.snapshot_date.strftime("%Y-%m-%d")
            if key not in aggregated:
                aggregated[key] = {
                    "date": key,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "total_open": 0,
                }
            aggregated[key]["critical"] += s.critical_count
            aggregated[key]["high"] += s.high_count
            aggregated[key]["medium"] += s.medium_count
            aggregated[key]["low"] += s.low_count
            aggregated[key]["total_open"] += s.total_open
        return sorted(aggregated.values(), key=lambda x: x["date"])

    def get_scan_frequency(
        self, session: Session, image_id: int
    ) -> dict[str, Any]:
        scans = (
            session.query(Scan.started_at, Scan.status, Scan.completed_at)
            .filter_by(image_id=image_id)
            .order_by(Scan.started_at.desc())
            .limit(50)
            .all()
        )
        if not scans:
            return {"total_scans": 0, "avg_interval_hours": None}
        total = len(scans)
        completed = sum(
            1 for s in scans
            if s.status is not None and s.status.value == "completed"
        )
        intervals = []
        timestamps = [s.started_at for s in scans if s.started_at]
        for i in range(1, len(timestamps)):
            diff = (timestamps[i - 1] - timestamps[i]).total_seconds() / 3600
            intervals.append(diff)
        return {
            "total_scans": total,
            "completed_scans": completed,
            "avg_interval_hours": round(
                sum(intervals) / len(intervals), 1
            ) if intervals else None,
            "last_scan": timestamps[0].isoformat() if timestamps else None,
        }

    def get_top_images_by_findings(
        self, session: Session, limit: int = 10
    ) -> list[dict]:
        results = []
        for img in session.query(Image).filter_by(active=True).all():
            critical = session.query(ScanFinding).filter_by(
                image_id=img.id, severity=Severity.CRITICAL, remediated=False
            ).count()
            high = session.query(ScanFinding).filter_by(
                image_id=img.id, severity=Severity.HIGH, remediated=False
            ).count()
            results.append({
                "image": img.full_name,
                "id": img.id,
                "critical": critical,
                "high": high,
                "total": critical + high +
                    session.query(ScanFinding).filter_by(
                        image_id=img.id, remediated=False
                    ).filter(
                        ScanFinding.severity.in_(
                            [Severity.MEDIUM, Severity.LOW])
                    ).count(),
            })
        results.sort(key=lambda x: x["critical"] * 10 + x["high"],
                     reverse=True)
        return results[:limit]
