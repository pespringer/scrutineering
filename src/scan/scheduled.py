"""Periodic scan scheduling over the active image inventory."""

from __future__ import annotations

from src.db.connection import get_session
from src.db.models import Image


def active_image_names(session) -> list[str]:
    return [image.full_name for image in session.query(Image).filter(Image.active.is_(True)).order_by(Image.id.asc()).all()]


def schedule_active_scans(enqueue, *, limit: int = 100) -> dict[str, int]:
    if limit < 1:
        raise ValueError("scan schedule limit must be positive")
    with get_session() as session:
        names = active_image_names(session)[:limit]
    for image_name in names:
        enqueue(image_name, priority="low")
    return {"discovered": len(names), "queued": len(names)}
