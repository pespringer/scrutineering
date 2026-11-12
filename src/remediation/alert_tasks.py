"""Local/deterministic alert delivery execution."""

from __future__ import annotations

import os
from datetime import datetime, timezone

from celery import shared_task

from src.db.connection import get_session
from src.db.models import RemediationAlertDelivery, RemediationAlertEvidence
from src.remediation.alert_delivery import dead_letter, receiver_for, schedule_retry
from src.telemetry.scan_metrics import record_alert_delivery


@shared_task(name="src.remediation.alert_tasks.deliver_alerts", acks_late=True)
def deliver_alerts(limit: int = 100) -> dict[str, int]:
    if os.environ.get("REMEDIATION_ALERT_DELIVERY_ENABLED", "false").lower() != "true":
        return {"delivered": 0, "retried": 0, "dead_lettered": 0, "disabled": 1}
    delivered = retried = dead = 0
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    with get_session() as session:
        records = session.query(RemediationAlertDelivery).filter(
            RemediationAlertDelivery.status.in_(["pending", "retrying"]),
            (RemediationAlertDelivery.next_attempt_at.is_(None) | (RemediationAlertDelivery.next_attempt_at <= now)),
        ).order_by(RemediationAlertDelivery.created_at.asc()).limit(limit).with_for_update(skip_locked=True).all()
        for record in records:
            record.attempts = (record.attempts or 0) + 1
            try:
                code, detail = receiver_for(record.receiver).deliver(record.payload)
                if code >= 400:
                    raise RuntimeError(detail)
                record.status = "delivered"
                record.last_error = None
                record.next_attempt_at = None
                delivered += 1
                record_alert_delivery("delivered")
                session.add(RemediationAlertEvidence(publication_id=record.publication_id, delivery_key=record.delivery_key, receiver=record.receiver, status="delivered", response_code=code, attempt=record.attempts, detail={"message": detail}))
            except Exception as exc:
                record.last_error = str(exc)[:1000]
                if record.attempts >= (record.max_attempts or 5):
                    dead_letter(record, record.last_error)
                    dead += 1
                    record_alert_delivery("dead_letter")
                else:
                    schedule_retry(record, now, increment=False)
                    retried += 1
                    record_alert_delivery("retrying")
    return {"delivered": delivered, "retried": retried, "dead_lettered": dead}
