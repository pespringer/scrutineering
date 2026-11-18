"""Write notifications into the outbox, in the same transaction as the status change.

A status change that rolls back sends nothing; one that commits is delivered even if the
process stops before sending it. Only `RemediationRepository.update_status` and the create
route call `record`, so every status change in `NOTIFICATION_EVENTS` is covered.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import event
from sqlalchemy.orm import Session

from src.config import Settings, get_settings
from src.db.models import Notification, Remediation, RemediationStatus
from src.remediation.state_machine import LABELS

logger = logging.getLogger(__name__)

MAX_ERROR = 300
_PENDING_KEY = "notifications_pending"


def now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def channels(settings: Settings) -> list[str]:
    """The channels that are configured. Slack joins this list in the next PR."""
    return ["webhook"] if settings.notification_webhook_url.get_secret_value() else []


def _first_line(text: str | None) -> str | None:
    if not text:
        return None
    line = text.strip().splitlines()[0] if text.strip() else ""
    return line[:MAX_ERROR] or None


def _pull_request_url(remediation: Remediation) -> str | None:
    opened = [item for item in remediation.publications if item.url and item.status in ("open", "merged")]
    return max(opened, key=lambda item: item.id).url if opened else None


def remediation_payload(remediation: Remediation, settings: Settings, occurred_at: datetime) -> dict:
    """What a message says, from the remediation as it is now. No source code, environment or tokens."""
    status = RemediationStatus(remediation.status)
    verification = remediation.verification or {}
    new_blocking = verification.get("new_critical_or_high") or []
    action = remediation.actions[0].action_type.value if remediation.actions else None
    base = settings.dashboard_public_url.rstrip("/")
    return {
        "event": f"remediation.{status.value}",
        "occurred_at": occurred_at.isoformat(timespec="seconds") + "Z",
        "remediation": {
            "id": remediation.id,
            "status": status.value,
            "label": LABELS[status],
            "image": remediation.image.full_name if remediation.image is not None else None,
            "action": action,
            "targets": remediation.finding_count,
            "new_critical_high": sorted({item.get("cve_id") for item in new_blocking if item.get("cve_id")}),
            "pull_request_url": _pull_request_url(remediation),
            "error": _first_line(remediation.error_message),
            "url": f"{base}/remediations/{remediation.id}" if base else None,
        },
    }


def record(session: Session, remediation_id: int, status: RemediationStatus) -> list[Notification]:
    """Queue a message to each configured channel when `status` is in `NOTIFICATION_EVENTS`."""
    settings = get_settings()
    configured = channels(settings)
    if not configured or RemediationStatus(status).value not in settings.notification_events:
        return []
    session.flush()
    remediation = session.get(Remediation, remediation_id, populate_existing=True)
    if remediation is None:
        return []
    occurred_at = now()
    payload = remediation_payload(remediation, settings, occurred_at)
    rows = [
        Notification(
            channel=channel,
            event=payload["event"],
            remediation_id=remediation_id,
            payload=payload,
            status="pending",
            attempts=0,
            next_attempt_at=occurred_at,
        )
        for channel in configured
    ]
    session.add_all(rows)
    session.flush()
    session.info[_PENDING_KEY] = True
    return rows


def sample_message(session: Session, settings: Settings | None = None) -> list[Notification]:
    """A sample message to each configured channel, through the same outbox and delivery."""
    settings = settings or get_settings()
    occurred_at = now()
    rows = [
        Notification(
            channel=channel,
            event="test",
            payload={
                "event": "test",
                "occurred_at": occurred_at.isoformat(timespec="seconds") + "Z",
                "message": "Scrutineering test notification",
            },
            status="pending",
            attempts=0,
            next_attempt_at=occurred_at,
        )
        for channel in channels(settings)
    ]
    session.add_all(rows)
    session.flush()
    if rows:
        session.info[_PENDING_KEY] = True
    return rows


def enqueue_delivery() -> None:
    """Ask a worker to deliver now. If the broker is down, the beat sweep delivers within a minute."""
    from src.notifications.delivery import deliver_pending

    try:
        deliver_pending.apply_async(queue="notify", retry=False)
    except Exception as exc:  # noqa: BLE001 - delivery is retried by the sweep
        logger.warning("could not queue notification delivery, the sweep will send it: %s", exc)


@event.listens_for(Session, "after_commit")
def _deliver_after_commit(session: Session) -> None:
    if session.info.pop(_PENDING_KEY, False):
        enqueue_delivery()


@event.listens_for(Session, "after_rollback")
def _forget_after_rollback(session: Session) -> None:
    session.info.pop(_PENDING_KEY, None)
