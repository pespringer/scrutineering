"""Durable provider recovery polling with bounded retries."""

from __future__ import annotations

import os
from datetime import datetime, timezone

from celery import shared_task

from src.db.connection import get_session
from src.db.models import RemediationRecoveryRequest
from src.db.repositories import RemediationRepository
from src.remediation.provider_status import fetch_provider_status
from src.remediation.recovery import retry_at, transition_recovery_status


def _token(provider: str) -> str | None:
    return os.environ.get("GITHUB_TOKEN" if provider == "github" else "GITLAB_TOKEN")


@shared_task(name="src.remediation.recovery_tasks.poll_recovery_requests", acks_late=True)
def poll_recovery_requests(limit: int = 100) -> dict[str, int]:
    """Poll requested callback recoveries and schedule bounded retries."""
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    processed = acknowledged = failed = retried = 0
    with get_session() as session:
        requests = session.query(RemediationRecoveryRequest).filter(
            RemediationRecoveryRequest.action == "request_callback",
            RemediationRecoveryRequest.status.in_(["requested", "acknowledged"]),
        ).order_by(RemediationRecoveryRequest.requested_at.asc()).limit(limit).all()
        for recovery in requests:
            if recovery.next_attempt_at and recovery.next_attempt_at > now:
                continue
            publication = recovery.publication
            processed += 1
            recovery.attempts += 1
            token = _token(publication.provider)
            try:
                if not token:
                    raise RuntimeError(f"missing token for {publication.provider}")
                if publication.provider_number is None:
                    raise RuntimeError("publication has no provider number")
                status = fetch_provider_status(provider=publication.provider, repository=publication.repository, number=publication.provider_number, token=token)
                if status.merged:
                    if recovery.status != "acknowledged":
                        transition_recovery_status(recovery.status, "acknowledged")
                        recovery.status = "acknowledged"
                        recovery.acknowledged_at = now
                        acknowledged += 1
                    recovery.error_message = None
                    recovery.next_attempt_at = None
                elif recovery.attempts >= recovery.max_attempts:
                    recovery.status = "failed"
                    recovery.completed_at = now
                    recovery.error_message = status.detail or "provider did not report a merged publication"
                    failed += 1
                else:
                    recovery.error_message = status.detail or "provider publication is not merged"
                    recovery.next_attempt_at = retry_at(now, recovery.attempts)
                    retried += 1
            except Exception as exc:
                recovery.error_message = str(exc)[:1000]
                if recovery.attempts >= recovery.max_attempts:
                    recovery.status = "failed"
                    recovery.completed_at = now
                    failed += 1
                else:
                    recovery.next_attempt_at = retry_at(now, recovery.attempts)
                    retried += 1
            events = RemediationRepository.list_events(session, publication.remediation_id)
            RemediationRepository.append_event(session, {
                "remediation_id": publication.remediation_id,
                "event_type": "publication_recovery_polled",
                "sequence": len(events) + 1,
                "detail": {"publication_id": publication.id, "recovery_request_id": recovery.id, "attempt": recovery.attempts, "status": recovery.status, "next_attempt_at": recovery.next_attempt_at.isoformat() if recovery.next_attempt_at else None},
            })
    return {"processed": processed, "acknowledged": acknowledged, "failed": failed, "retried": retried}
