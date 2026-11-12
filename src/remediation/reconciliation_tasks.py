"""Scheduled stale-publication reconciliation task."""

from __future__ import annotations

import os
from datetime import datetime, timezone

from celery import shared_task

from src.db.connection import get_session
from src.db.models import RemediationPublication, RemediationReconciliationRun
from src.db.repositories import RemediationRepository
from src.remediation.events import publication_event_exists
from src.remediation.reconciliation import publication_age_seconds, publication_is_stale
from src.telemetry.scan_metrics import record_reconciliation_run, record_recovery_escalation


def stale_threshold_seconds() -> int:
    return min(max(int(os.environ.get("REMEDIATION_PUBLICATION_STALE_SECONDS", "900")), 60), 604800)


def escalation_age_seconds(threshold: int) -> int:
    return threshold * min(max(int(os.environ.get("REMEDIATION_PUBLICATION_ESCALATION_CYCLES", "3")), 2), 10)


@shared_task(
    name="src.remediation.reconciliation_tasks.reconcile_stale_publications",
    acks_late=True,
)
def reconcile_stale_publications(limit: int = 250) -> dict[str, int]:
    """Record one durable operator event for each newly stale publication."""
    threshold = stale_threshold_seconds()
    now = datetime.now(timezone.utc)
    discovered = 0
    recorded = 0
    with get_session() as session:
        run = RemediationReconciliationRun(status="running")
        session.add(run)
        session.flush()
        try:
            records = session.query(RemediationPublication).filter(
                RemediationPublication.status.in_(["pending", "failed", "merged"]),
            ).order_by(RemediationPublication.created_at.asc()).limit(limit).all()
            for publication in records:
                if not publication_is_stale(publication, stale_after_seconds=threshold, now=now):
                    continue
                discovered += 1
                detail = {
                    "publication_id": publication.id,
                    "status": publication.status,
                    "age_seconds": publication_age_seconds(publication, now=now),
                    "stale_after_seconds": threshold,
                }
                events = RemediationRepository.list_events(session, publication.remediation_id)
                if publication_event_exists(events, event_type="publication_stale", publication_id=publication.id, detail=detail):
                    if detail["age_seconds"] >= escalation_age_seconds(threshold) and not any(event.event_type == "publication_recovery_escalated" and event.detail.get("publication_id") == publication.id for event in events):
                        RemediationRepository.append_event(session, {
                            "remediation_id": publication.remediation_id,
                            "event_type": "publication_recovery_escalated",
                            "sequence": len(events) + 1,
                            "detail": {**detail, "reason": "publication remained stale beyond escalation window"},
                        })
                        record_recovery_escalation()
                        recorded += 1
                    continue
                RemediationRepository.append_event(session, {
                    "remediation_id": publication.remediation_id,
                    "event_type": "publication_stale",
                    "sequence": len(events) + 1,
                    "detail": detail,
                })
                recorded += 1
            run.status = "completed"
            run.discovered = discovered
            run.events_recorded = recorded
        except Exception as exc:
            run.status = "failed"
            run.error_message = str(exc)[:1000]
            run.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
            record_reconciliation_run("failed")
            return {"discovered": discovered, "events_recorded": recorded, "stale_after_seconds": threshold, "status": "failed"}
        run.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
    record_reconciliation_run("completed")
    return {"discovered": discovered, "events_recorded": recorded, "stale_after_seconds": threshold}
