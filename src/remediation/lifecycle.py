"""Status changes that follow from facts the server observed itself."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.db.models import Remediation, RemediationStatus, Scan, ScanFinding
from src.db.repositories import RemediationRepository

WAITING = (RemediationStatus.READY, RemediationStatus.PUBLISHED)


def targeted_vuln_keys(remediation: Remediation) -> set[str]:
    return {finding.vuln_key for finding in remediation.findings}


def _merged_publication(remediation: Remediation):
    return next((item for item in remediation.publications if item.status == "merged"), None)


def complete_verified_remediations(session: Session, image_id: int, scan_id: str) -> list[int]:
    """After a complete scan of an image, settle each ready or published remediation it decides.

    - Every targeted `vuln_key` is gone (no open finding carries it, at any version): `completed`.
    - The pull request was merged and this scan is of a rebuilt image (its digest differs from the
      image's digest when the pull request was opened), yet a target remains: `failed`.
    - Otherwise nothing changes: the image has not been rebuilt from the fix yet.

    Returns the ids of remediations completed.
    """
    open_keys = set(
        session.execute(
            select(ScanFinding.vuln_key).where(ScanFinding.image_id == image_id, ScanFinding.resolved_at.is_(None))
        ).scalars()
    )
    scan_digest = session.execute(select(Scan.image_digest).where(Scan.scan_id == scan_id)).scalar_one_or_none()
    completed = []
    waiting = session.execute(
        select(Remediation).where(Remediation.image_id == image_id, Remediation.status.in_(WAITING))
    ).unique()
    for remediation in waiting.scalars():
        targets = targeted_vuln_keys(remediation)
        if not targets:
            continue
        remaining = targets & open_keys
        if not remaining:
            RemediationRepository.update_status(session, remediation.id, RemediationStatus.COMPLETED)
            RemediationRepository.record_event(
                session, remediation.id, "completed", {"scan_id": scan_id, "vuln_keys": sorted(targets)}
            )
            completed.append(remediation.id)
            continue
        merged = _merged_publication(remediation) if remediation.status == RemediationStatus.PUBLISHED else None
        if merged and merged.image_digest and scan_digest and scan_digest != merged.image_digest:
            reason = (
                f"the image was rebuilt after pull request #{merged.provider_number} merged ({scan_digest}), "
                f"but it still has {len(remaining)} of the targeted findings"
            )
            RemediationRepository.update_status(session, remediation.id, RemediationStatus.FAILED, error_message=reason)
            RemediationRepository.record_event(
                session,
                remediation.id,
                "failed",
                {"scan_id": scan_id, "reason": reason, "vuln_keys": sorted(remaining)},
            )
    return completed
