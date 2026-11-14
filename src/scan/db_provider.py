"""SQLAlchemy adapter for the versioned scan-data API."""

from __future__ import annotations

from typing import Any, Callable

from sqlalchemy import select
from sqlalchemy.orm import joinedload

from src.db.models import AuditLog, Scan, ScanFinding, Severity


class SqlAlchemyScanDataProvider:
    """Read-only provider that keeps API serialization out of route handlers."""

    def __init__(self, session_factory: Callable, alert_provider: Callable | None = None):
        self.session_factory = session_factory
        self.alert_provider = alert_provider

    @staticmethod
    def _scan_dict(scan: Scan) -> dict[str, Any]:
        return {
            "scan_id": scan.scan_id,
            "status": scan.status.value,
            "image": scan.image.full_name if scan.image else None,
            "image_digest": scan.image_digest or (scan.image.digest if scan.image else None),
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "total_findings": scan.total_findings,
        }

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        with self.session_factory() as session:
            scan = session.execute(select(Scan).where(Scan.scan_id == scan_id)).scalar_one_or_none()
            return self._scan_dict(scan) if scan else None

    def list_findings(self, **filters: Any) -> list[dict[str, Any]]:
        with self.session_factory() as session:
            query = select(ScanFinding).options(joinedload(ScanFinding.image))
            severity = filters.get("severity")
            if severity:
                try:
                    query = query.where(ScanFinding.severity == Severity(severity.lower()))
                except ValueError:
                    return []
            if filters.get("image_digest"):
                query = query.join(ScanFinding.image).where(ScanFinding.image.has(digest=filters["image_digest"]))
            rows = session.execute(query.order_by(ScanFinding.first_seen.desc())).scalars().all()
            return [{
                "fingerprint": row.fingerprint,
                "cve_id": row.cve_id,
                "package_name": row.package_name,
                "severity": row.severity.value if row.severity else None,
                "image_digest": row.image.digest if row.image else None,
                "remediated": row.remediated,
                "resolved_at": row.resolved_at.isoformat() if row.resolved_at else None,
                "reopened_at": row.reopened_at.isoformat() if row.reopened_at else None,
                "lifecycle_status": "resolved" if row.resolved_at else "open",
            } for row in rows]

    def list_alerts(self, **filters: Any) -> list[dict[str, Any]]:
        return list(self.alert_provider(filters) if self.alert_provider else [])

    def list_audit(self, **filters: Any) -> list[dict[str, Any]]:
        with self.session_factory() as session:
            query = select(AuditLog)
            if filters.get("actor"):
                query = query.where(AuditLog.actor == filters["actor"])
            if filters.get("event_type"):
                query = query.where(AuditLog.event_type == filters["event_type"])
            rows = session.execute(query.order_by(AuditLog.timestamp.desc())).scalars().all()
            return [{
                "id": row.id,
                "timestamp": row.timestamp.isoformat() if row.timestamp else None,
                "event_type": row.event_type.value,
                "actor": row.actor,
                "detail": row.detail,
            } for row in rows]
