"""Notification channels: which are configured, recent deliveries, and a test send.

Channel URLs and the webhook secret never leave the server: the page learns only whether
each channel is configured.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import select

from src.api.routes._access import require_role
from src.api.serializers import iso
from src.config import get_settings
from src.db.connection import get_session
from src.db.models import Notification
from src.notifications import outbox

router = APIRouter()

CHANNELS = ("slack", "webhook")
RECENT = 20


def _delivery(row: Notification) -> dict:
    return {
        "id": row.id,
        "channel": row.channel,
        "event": row.event,
        "remediation_id": row.remediation_id,
        "status": row.status,
        "attempts": row.attempts,
        "last_error": row.last_error,
        "created_at": iso(row.created_at),
        "sent_at": iso(row.sent_at),
        "next_attempt_at": iso(row.next_attempt_at) if row.status == "pending" else None,
    }


@router.get("/notifications")
def notifications(request: Request) -> dict:
    require_role(request, "security-operator")
    settings = get_settings()
    configured = set(outbox.channels(settings))
    with get_session() as session:
        rows = session.execute(select(Notification).order_by(Notification.id.desc()).limit(RECENT)).scalars().all()
        deliveries = [_delivery(row) for row in rows]
    return {
        "channels": [{"name": name, "configured": name in configured} for name in CHANNELS],
        "events": settings.notification_events,
        "links": bool(settings.dashboard_public_url),
        "deliveries": deliveries,
    }


@router.post("/notifications/test", status_code=202)
def send_test(request: Request) -> dict:
    """Queue a sample message to every configured channel, through the normal outbox and delivery."""
    require_role(request, "security-operator")
    settings = get_settings()
    if not outbox.channels(settings):
        raise HTTPException(status_code=409, detail="no_notification_channel_configured")
    with get_session() as session:
        rows = outbox.sample_message(session, settings)
        queued = [_delivery(row) for row in rows]
    return {"queued": queued}
