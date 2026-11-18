"""Send pending notifications: one row at a time, locked, with retries and a final `failed`.

Delivery is at least once. A crash between the POST and the update repeats a message; the
webhook carries the delivery ID so receivers can drop the repeat.
"""

from __future__ import annotations

import logging
from datetime import timedelta

import httpx
from celery import shared_task
from sqlalchemy import delete, select

from src.config import Settings, get_settings
from src.db.connection import get_session
from src.db.models import Notification
from src.notifications import webhook
from src.notifications.outbox import now

logger = logging.getLogger(__name__)

# Delays after the 1st, 2nd, 3rd and 4th failed attempt; the 5th failure is final.
RETRY_DELAYS = (timedelta(minutes=1), timedelta(minutes=5), timedelta(minutes=15), timedelta(minutes=60))
MAX_ATTEMPTS = len(RETRY_DELAYS) + 1
TIMEOUT_SECONDS = 10.0
SENT_RETENTION = timedelta(days=30)
BATCH = 50
transport: httpx.BaseTransport | None = None  # tests substitute an in-process receiver


class DeliveryError(Exception):
    """A message was not accepted. The text never contains the destination URL."""


def _post(url: str, raw: bytes, headers: dict[str, str]) -> None:
    try:
        with httpx.Client(timeout=TIMEOUT_SECONDS, follow_redirects=False, transport=transport) as client:
            response = client.post(url, content=raw, headers=headers)
    except httpx.HTTPError as exc:
        raise DeliveryError(f"{type(exc).__name__}: could not reach the receiver") from None
    if not 200 <= response.status_code < 300:
        raise DeliveryError(f"HTTP {response.status_code}")


def send(notification: Notification, settings: Settings) -> None:
    """Deliver one message to its channel, or raise DeliveryError."""
    if notification.channel == "webhook":
        url = settings.notification_webhook_url.get_secret_value()
        if not url:
            raise DeliveryError("NOTIFICATION_WEBHOOK_URL is no longer set")
        raw, headers = webhook.request(
            notification.id,
            notification.event,
            notification.payload,
            settings.notification_webhook_secret.get_secret_value(),
        )
        _post(url, raw, headers)
        return
    raise DeliveryError(f"unknown channel {notification.channel!r}")


def _deliver_next(settings: Settings) -> Notification | None:
    """Claim, send and update the next due row; None when nothing is due."""
    with get_session() as session:
        notification = session.execute(
            select(Notification)
            .where(Notification.status == "pending", Notification.next_attempt_at <= now())
            .order_by(Notification.next_attempt_at, Notification.id)
            .limit(1)
            .with_for_update(skip_locked=True)
        ).scalar_one_or_none()
        if notification is None:
            return None
        notification.attempts += 1
        try:
            send(notification, settings)
        except DeliveryError as exc:
            notification.last_error = str(exc)[:500]
            if notification.attempts >= MAX_ATTEMPTS:
                notification.status = "failed"
                logger.warning("notification %s failed after %s attempts: %s", notification.id, MAX_ATTEMPTS, exc)
            else:
                notification.next_attempt_at = now() + RETRY_DELAYS[notification.attempts - 1]
        else:
            notification.status = "sent"
            notification.sent_at = now()
            notification.last_error = None
        return notification


def deliver(limit: int = BATCH) -> dict:
    """Send what is due, then delete sent rows older than 30 days. Failed rows are kept."""
    settings = get_settings()
    counts = {"sent": 0, "retrying": 0, "failed": 0}
    for _ in range(limit):
        notification = _deliver_next(settings)
        if notification is None:
            break
        counts["retrying" if notification.status == "pending" else notification.status] += 1
    with get_session() as session:
        counts["deleted"] = session.execute(
            delete(Notification).where(Notification.status == "sent", Notification.sent_at < now() - SENT_RETENTION)
        ).rowcount
    return counts


@shared_task(name="src.notifications.delivery.deliver_pending", acks_late=True, ignore_result=True)
def deliver_pending() -> dict:
    """Queued after each commit that wrote notifications, and every minute by beat as a sweep."""
    return deliver()
