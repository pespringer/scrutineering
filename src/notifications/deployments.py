"""`remediation.deployment_stale`: a completed fix whose containers still run an older build.

See docs/design/deployment-observation.md. A sweep (every 15 minutes, after discovery) sends it
once per remediation, when the fix completed at least 24 hours ago and some running container
still isn't on a fixed build. A fix that completed more than 72 hours ago is never announced, so
configuring a channel later doesn't flood it with old fixes. Whether it was sent is read from the
outbox, the only record of what was queued; the remediation's status is never derived from it.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

from celery import shared_task

logger = logging.getLogger(__name__)

STALE_AFTER = timedelta(hours=24)
NEWEST_ANNOUNCED = timedelta(hours=72)


def sweep(now: datetime | None = None) -> int:
    """Queue the notification for each fix that is due. Returns how many fixes were announced."""
    from src.config import get_settings
    from src.db.connection import get_session
    from src.db.models import Notification, Remediation, RemediationStatus
    from src.notifications.outbox import DEPLOYMENT_STALE, channels, record_deployment_stale
    from src.scan.deployments import remediation_deployment, utcnow

    settings = get_settings()
    if not channels(settings) or "deployment_stale" not in settings.notification_events:
        return 0
    now = now or utcnow()
    announced = 0
    with get_session() as session:
        already = session.query(Notification.remediation_id).filter(
            Notification.event == DEPLOYMENT_STALE, Notification.remediation_id.is_not(None)
        )
        completed = (
            session.query(Remediation)
            .filter(
                Remediation.status == RemediationStatus.COMPLETED,
                Remediation.completed_at.is_not(None),
                Remediation.id.not_in(already),
            )
            .order_by(Remediation.id)
            .all()
        )
        # Compared in Python, as for evidence: SQLite stores server and Python timestamps differently.
        due = [item for item in completed if now - NEWEST_ANNOUNCED < item.completed_at <= now - STALE_AFTER]
        for remediation in due:
            deployment = remediation_deployment(session, remediation, now)
            if not deployment or deployment["fixed"] is None or not deployment["not_fixed"]:
                continue
            if record_deployment_stale(session, remediation, deployment):
                announced += 1
    if announced:
        logger.info("announced %d fixes whose containers still run an older build", announced)
    return announced


@shared_task(name="src.notifications.deployments.notify_stale_deployments", acks_late=True, ignore_result=True)
def notify_stale_deployments() -> int:
    """Every 15 minutes, from beat."""
    return sweep()
