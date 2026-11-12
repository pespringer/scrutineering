"""Receiver-independent alert queue and dead-letter lifecycle."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os

from src.db.models import RemediationAlertDelivery
from src.remediation.alert_contracts import validate_alert_payload
from src.remediation.alert_governance import QueuePolicy


class FakeReceiver:
    """Deterministic local receiver used by drills; never performs network I/O."""
    def deliver(self, payload: dict) -> tuple[int, str]:
        if payload.get("simulate_failure"):
            return 503, "simulated receiver failure"
        return 202, "accepted by deterministic fake receiver"


def receiver_for(name: str):
    if name == "fake":
        return FakeReceiver()
    raise ValueError("receiver is not configured for local execution")


def sanitize_payload(payload: dict) -> dict:
    """Remove credential-like fields before persisting or delivering alerts."""
    blocked = {"token", "secret", "authorization", "password"}
    return {key: ("[REDACTED]" if key.lower() in blocked else value) for key, value in payload.items()}


def delivery_key(publication_id: int, receiver: str, event_type: str, payload: dict) -> str:
    canonical = json.dumps({"publication_id": publication_id, "receiver": receiver, "event_type": event_type, "payload": payload}, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def enqueue_delivery(session, *, publication_id: int, receiver: str, event_type: str, payload: dict):
    QueuePolicy(max_batch=100).validate(priority=payload.get("priority", "normal"))
    key = delivery_key(publication_id, receiver, event_type, payload)
    existing = session.query(RemediationAlertDelivery).filter_by(publication_id=publication_id, delivery_key=key).first()
    if existing:
        return existing, True
    record = RemediationAlertDelivery(publication_id=publication_id, delivery_key=key, receiver=receiver, max_attempts=min(max(int(os.environ.get("REMEDIATION_ALERT_MAX_ATTEMPTS", "5")), 1), 100), payload=validate_alert_payload({"event_type": event_type, "publication_id": publication_id, **sanitize_payload(payload)}))
    session.add(record)
    session.flush()
    return record, False


def dead_letter(record: RemediationAlertDelivery, error: str) -> None:
    record.status = "dead_letter"
    record.last_error = error[:1000]
    record.next_attempt_at = None


def schedule_retry(record: RemediationAlertDelivery, now: datetime | None = None, *, increment: bool = True) -> None:
    current = now or datetime.now(timezone.utc).replace(tzinfo=None)
    record.status = "retrying"
    if increment:
        record.attempts = (record.attempts or 0) + 1
    max_attempts = record.max_attempts or 5
    if record.attempts >= max_attempts:
        dead_letter(record, record.last_error or "maximum delivery attempts exceeded")
        return
    record.next_attempt_at = current + timedelta(seconds=min(300, 15 * 2 ** max(0, record.attempts - 1)))
