"""Receiver-independent alert queue and dead-letter lifecycle."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os

from src.db.models import RemediationAlertDelivery


def delivery_key(publication_id: int, receiver: str, event_type: str, payload: dict) -> str:
    canonical = json.dumps({"publication_id": publication_id, "receiver": receiver, "event_type": event_type, "payload": payload}, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def enqueue_delivery(session, *, publication_id: int, receiver: str, event_type: str, payload: dict):
    key = delivery_key(publication_id, receiver, event_type, payload)
    existing = session.query(RemediationAlertDelivery).filter_by(publication_id=publication_id, delivery_key=key).first()
    if existing:
        return existing, True
    record = RemediationAlertDelivery(publication_id=publication_id, delivery_key=key, receiver=receiver, max_attempts=min(max(int(os.environ.get("REMEDIATION_ALERT_MAX_ATTEMPTS", "5")), 1), 100), payload={"event_type": event_type, **payload})
    session.add(record)
    session.flush()
    return record, False


def dead_letter(record: RemediationAlertDelivery, error: str) -> None:
    record.status = "dead_letter"
    record.last_error = error[:1000]
    record.next_attempt_at = None


def schedule_retry(record: RemediationAlertDelivery, now: datetime | None = None) -> None:
    current = now or datetime.now(timezone.utc).replace(tzinfo=None)
    record.status = "retrying"
    record.attempts = (record.attempts or 0) + 1
    max_attempts = record.max_attempts or 5
    if record.attempts >= max_attempts:
        dead_letter(record, record.last_error or "maximum delivery attempts exceeded")
        return
    record.next_attempt_at = current + timedelta(seconds=min(300, 15 * 2 ** max(0, record.attempts - 1)))
