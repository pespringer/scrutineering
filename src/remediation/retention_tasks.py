"""Safe, opt-in evidence retention task."""

from __future__ import annotations

from celery import shared_task

from src.db.connection import get_session
from src.db.models import RemediationAlertEvidence, RemediationReleaseEvidence
from src.remediation.evidence_retention import purge_enabled, retention_cutoff


@shared_task(name="src.remediation.retention_tasks.purge_expired_evidence", acks_late=True)
def purge_expired_evidence(*, dry_run: bool = True, limit: int = 500) -> dict[str, int | bool]:
    cutoff = retention_cutoff()
    with get_session() as session:
        releases = session.query(RemediationReleaseEvidence).filter(RemediationReleaseEvidence.created_at < cutoff).limit(limit).all()
        alerts = session.query(RemediationAlertEvidence).filter(RemediationAlertEvidence.created_at < cutoff).limit(limit).all()
        eligible = len(releases) + len(alerts)
        purged = 0
        if not dry_run and purge_enabled():
            for item in [*releases, *alerts]:
                session.delete(item)
            purged = eligible
    return {"dry_run": dry_run, "purge_enabled": purge_enabled(), "eligible": eligible, "purged": purged}
