"""Asynchronous post-merge scan scheduling and evidence capture."""

from __future__ import annotations

import os
from pathlib import Path

from celery import shared_task

from src.db.connection import get_session
from src.db.models import RemediationPublication, Scan, ScanStatus
from src.db.repositories import RemediationRepository


def post_merge_scan_target(publication: RemediationPublication) -> str:
    """Return the image or filesystem target that should be rescanned."""
    image = publication.remediation.image
    if image is None:
        raise ValueError("publication remediation image is required")
    if image.tag == "filesystem" and image.repo_name.startswith("local/"):
        root = Path(os.environ.get("REMEDIATION_SCAN_REPOSITORY_ROOT", "/workspace/repository"))
        return f"fs:{(root / image.repo_name.removeprefix('local/')).resolve()}"
    return image.full_name


def queue_post_merge_scan(session, publication: RemediationPublication) -> str:
    """Queue one idempotent follow-up scan and persist its correlation ID."""
    if publication.post_merge_scan_id:
        return publication.post_merge_scan_id
    scan_id = f"postmerge-{publication.id}"
    from src.scan.tasks import enqueue_scan
    enqueue_scan(post_merge_scan_target(publication), priority="high", scan_id=scan_id)
    publication.post_merge_scan_id = scan_id
    publication.scan_status = "pending"
    return scan_id


def _append_event(session, publication: RemediationPublication, event_type: str, detail: dict) -> None:
    events = RemediationRepository.list_events(session, publication.remediation_id)
    if any(event.event_type == event_type and event.detail.get("publication_id") == publication.id for event in events):
        return
    RemediationRepository.append_event(session, {
        "remediation_id": publication.remediation_id,
        "event_type": event_type,
        "sequence": len(events) + 1,
        "detail": {"publication_id": publication.id, **detail},
    })


@shared_task(bind=True, name="src.remediation.post_merge_tasks.verify_post_merge_scan", acks_late=True)
def verify_post_merge_scan(self, publication_id: int, scan_id: str) -> dict:
    """Persist follow-up scan results without inventing deployment evidence."""
    with get_session() as session:
        publication = session.get(RemediationPublication, publication_id)
        if publication is None:
            return {"publication_id": publication_id, "status": "not_found"}
        scan = session.query(Scan).filter_by(scan_id=scan_id).first()
        if scan is None or scan.status in {ScanStatus.PENDING, ScanStatus.RUNNING}:
            raise self.retry(countdown=10, max_retries=30)
        publication.scan_status = scan.status.value if hasattr(scan.status, "value") else str(scan.status)
        publication.findings_after = scan.total_findings or 0
        publication.findings_before = publication.findings_before if publication.findings_before is not None and publication.findings_before > 0 else publication.remediation.finding_count
        if publication.scan_status in {ScanStatus.FAILED.value, ScanStatus.CANCELLED.value}:
            publication.verification_status = "rollback_required"
            publication.verification_detail = {"status": "rollback_required", "reasons": ["post-merge scan did not complete"], "scan_id": scan_id}
            _append_event(session, publication, "post_merge_scan_failed", publication.verification_detail)
            return {"publication_id": publication_id, "scan_id": scan_id, "status": publication.verification_status}
        publication.verification_status = "pending"
        publication.verification_detail = {
            "status": "pending",
            "scan_id": scan_id,
            "findings_before": publication.findings_before,
            "findings_after": publication.findings_after,
            "reason": "deployment_digest_evidence_required",
        }
        _append_event(session, publication, "post_merge_scan_completed", publication.verification_detail)
        return {"publication_id": publication_id, "scan_id": scan_id, "status": publication.verification_status, "findings_after": publication.findings_after}
