"""Periodic scan scheduling over the active image inventory."""

from __future__ import annotations

from src.db.connection import get_session
from src.db.models import Image
from src.scan.reliability import ScanCooldown, cooldown_active
from src.telemetry.scan_metrics import set_queue_health


def active_image_names(session) -> list[str]:
    return [image.full_name for image in session.query(Image).filter(Image.active.is_(True)).order_by(Image.id.asc()).all()]


def schedule_active_scans(enqueue, *, limit: int = 100, cooldown: ScanCooldown | None = None, now=None) -> dict[str, int]:
    if limit < 1:
        raise ValueError("scan schedule limit must be positive")
    policy = cooldown or ScanCooldown(0)
    with get_session() as session:
        images = session.query(Image).filter(Image.active.is_(True)).order_by(Image.id.asc()).all()[:limit]
        names = [image.full_name for image in images if not cooldown_active(getattr(image, "last_scan_at", None), policy=policy, now=now)]
    for image_name in names:
        enqueue(image_name, priority="low")
    set_queue_health("scan.low", len(names), 0)
    return {"discovered": len(images), "queued": len(names), "suppressed": len(images) - len(names)}
