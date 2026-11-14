"""Queue and evaluate durable post-remediation verification scans."""

from __future__ import annotations

import os
from pathlib import Path
import uuid

from celery import shared_task

from src.db.connection import get_session
from src.db.models import Remediation, Scan, ScanFinding, ScanStatus
from src.db.repositories import RemediationRepository


def remediation_scan_target(remediation: Remediation) -> str:
    image = remediation.image
    if image is None:
        raise ValueError("remediation image is required")
    if image.tag == "filesystem" and image.repo_name.startswith("local/"):
        root = Path(os.environ.get("REMEDIATION_SCAN_REPOSITORY_ROOT", "/workspace/repository"))
        return f"fs:{(root / image.repo_name.removeprefix('local/')).resolve()}"
    return image.full_name


def queue_remediation_verification_scan(session, remediation: Remediation) -> str:
    """Queue one idempotent high-priority scan for a completed remediation."""
    if remediation.verification_scan_id and remediation.verification_status in {"pending", "passed"}:
        return remediation.verification_scan_id
    scan_id = f"remediation-verify-{remediation.id}-{uuid.uuid4().hex[:8]}"
    from src.scan.tasks import enqueue_scan
    enqueue_scan(remediation_scan_target(remediation), priority="high", scan_id=scan_id)
    remediation.verification_scan_id = scan_id
    remediation.verification_status = "pending"
    remediation.verification_error = None
    remediation.verification_findings_before = remediation.finding_count
    events = RemediationRepository.list_events(session, remediation.id)
    RemediationRepository.append_event(session, {
        "remediation_id": remediation.id,
        "event_type": "verification_scan_queued",
        "sequence": len(events) + 1,
        "detail": {"scan_id": scan_id, "findings_before": remediation.finding_count},
    })
    return scan_id


@shared_task(bind=True, name="src.remediation.verification_tasks.verify_remediation_scan", acks_late=True)
def verify_remediation_scan(self, remediation_id: int, scan_id: str) -> dict:
    """Evaluate terminal scan findings against the remediation action coordinates."""
    with get_session() as session:
        remediation = session.get(Remediation, remediation_id)
        if remediation is None:
            return {"remediation_id": remediation_id, "status": "not_found"}
        scan = session.query(Scan).filter_by(scan_id=scan_id).first()
        if scan is None or scan.status in {ScanStatus.PENDING, ScanStatus.RUNNING}:
            raise self.retry(countdown=10, max_retries=30)
        scan_status = scan.status.value if hasattr(scan.status, "value") else str(scan.status)
        remediation.verification_findings_after = scan.total_findings or 0
        if scan_status in {ScanStatus.FAILED.value, ScanStatus.PARTIAL.value, ScanStatus.CANCELLED.value}:
            remediation.verification_status = "failed"
            remediation.verified = False
            remediation.verification_error = scan.error_message or f"verification_scan_{scan_status}"
            remaining = []
        else:
            findings = session.query(ScanFinding).filter_by(scan_id=scan_id).all()
            remaining = []
            for action in remediation.actions:
                detail = action.detail or {}
                package_name = detail.get("package_name")
                cve_id = detail.get("cve_id")
                if any(
                    package_name and finding.package_name == package_name and (not cve_id or finding.cve_id == cve_id)
                    for finding in findings
                ):
                    remaining.append({"package_name": package_name, "cve_id": cve_id})
            remediation.verification_status = "passed" if not remaining else "failed"
            remediation.verified = not remaining
            remediation.verification_error = None if not remaining else "remediated findings remain in verification scan"
        events = RemediationRepository.list_events(session, remediation_id)
        detail = {
            "scan_id": scan_id,
            "scan_status": scan_status,
            "findings_before": remediation.verification_findings_before,
            "findings_after": remediation.verification_findings_after,
            "remaining": remaining,
        }
        RemediationRepository.append_event(session, {
            "remediation_id": remediation_id,
            "event_type": "verification_scan_completed",
            "sequence": len(events) + 1,
            "detail": detail,
        })
        return {"remediation_id": remediation_id, "scan_id": scan_id, "status": remediation.verification_status, **detail}
