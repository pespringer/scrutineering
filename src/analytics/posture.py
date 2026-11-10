"""Security posture metrics for the Container Sentinel dashboard.

Provides aggregate metrics about the overall security posture.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

from src.db.models import Image, Scan, ScanFinding, Severity, ScanStatus

SEVERITY_WEIGHTS = {"critical": 10, "high": 5, "medium": 2, "low": 1, "unknown": 0.5}


class SecurityPostureService:
    def get_overview(self, session: Session) -> dict[str, Any]:
        images = session.query(Image).filter_by(active=True).all()
        images_count = len(images)
        findings_by_sev = self._findings_by_severity(session)
        total_findings = sum(findings_by_sev.values())
        fixable = self._fixable_count(session)
        risk_score = self._risk_score(session, findings_by_sev)

        return {
            "total_images": images_count,
            "active_scans": session.query(Scan).filter_by(
                status=ScanStatus.RUNNING).count(),
            "total_findings": total_findings,
            "findings_by_severity": findings_by_sev,
            "fixable_findings": fixable,
            "fixable_percent": round(
                fixable / total_findings * 100, 1) if total_findings else 0,
            "risk_score": risk_score,
            "risk_level": self._risk_level(risk_score),
        }

    def get_image_posture(self, session, image_id):
        img = session.query(Image).get(image_id)
        if not img:
            return None
        last_scan = (
            session.query(Scan).filter_by(image_id=image_id)
            .order_by(Scan.started_at.desc()).first()
        )
        findings_by_sev = {}
        for sev in Severity:
            cnt = session.query(ScanFinding).filter_by(
                image_id=image_id, severity=sev, remediated=False
            ).count()
            findings_by_sev[sev.value] = cnt
        total = sum(findings_by_sev.values())
        risk = sum(
            SEVERITY_WEIGHTS.get(k, 0) * v for k, v in findings_by_sev.items()
        )
        return {
            "image": img.full_name,
            "active": img.active,
            "last_scan": last_scan.started_at.isoformat() if last_scan else None,
            "last_scan_status": last_scan.status.value if last_scan and last_scan.status else None,
            "findings_by_severity": findings_by_sev,
            "total_findings": total,
            "risk_score": risk,
            "risk_level": self._risk_level(risk),
        }

    def get_container_inventory(self, session):
        images = session.query(Image).filter_by(active=True).all()
        result = []
        for img in images:
            last_scan = (
                session.query(Scan).filter_by(image_id=img.id)
                .order_by(Scan.started_at.desc()).first()
            )
            fc = session.query(ScanFinding).filter_by(
                image_id=img.id, remediated=False).count()
            result.append({
                "id": img.id,
                "name": img.full_name,
                "registry": img.registry_name.value,
                "status": (last_scan.status.value if last_scan and last_scan.status else "never_scanned"),
                "last_scan": last_scan.started_at.isoformat() if last_scan else None,
                "open_findings": fc,
            })
        return result

    def _findings_by_severity(self, session):
        result = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for sev in Severity:
            result[sev.value] = session.query(ScanFinding).filter_by(
                severity=sev, remediated=False
            ).count()
        return result

    def _fixable_count(self, session):
        return session.query(ScanFinding).filter_by(
            remediated=False, fix_available=True
        ).count()

    def _risk_score(self, session, findings_by_sev):
        return sum(
            SEVERITY_WEIGHTS.get(k, 0) * v
            for k, v in findings_by_sev.items()
        )

    def _risk_level(self, score):
        if score >= 100:
            return "critical"
        elif score >= 50:
            return "high"
        elif score >= 20:
            return "medium"
        elif score > 0:
            return "low"
        return "clean"
