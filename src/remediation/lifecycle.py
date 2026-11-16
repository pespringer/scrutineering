"""Status changes that follow from facts the server observed itself."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.db.models import Remediation, RemediationStatus, ScanFinding
from src.db.repositories import RemediationRepository


def targeted_vuln_keys(remediation: Remediation) -> set[str]:
    return {finding.vuln_key for finding in remediation.findings}


def complete_verified_remediations(session: Session, image_id: int, scan_id: str) -> list[int]:
    """After a complete scan of an image, complete each ready remediation whose targets are all gone.

    "Gone" means no open finding on the image carries a targeted `vuln_key`, at any version.
    Returns the ids of remediations completed.
    """
    open_keys = set(
        session.execute(
            select(ScanFinding.vuln_key).where(ScanFinding.image_id == image_id, ScanFinding.resolved_at.is_(None))
        ).scalars()
    )
    completed = []
    ready = session.execute(
        select(Remediation).where(Remediation.image_id == image_id, Remediation.status == RemediationStatus.READY)
    ).unique()
    for remediation in ready.scalars():
        targets = targeted_vuln_keys(remediation)
        if not targets or targets & open_keys:
            continue
        RemediationRepository.update_status(session, remediation.id, RemediationStatus.COMPLETED)
        RemediationRepository.record_event(
            session, remediation.id, "completed", {"scan_id": scan_id, "vuln_keys": sorted(targets)}
        )
        completed.append(remediation.id)
    return completed
