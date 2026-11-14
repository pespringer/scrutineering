"""Periodic scan scheduling over the active image inventory."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from src.db.connection import get_session
from src.db.models import Image, ScanSchedule
from src.scan.reliability import ScanCooldown, cooldown_active
from src.telemetry.scan_metrics import set_queue_health


def active_image_names(session) -> list[str]:
    return [image.full_name for image in session.query(Image).filter(Image.active.is_(True)).order_by(Image.id.asc()).all()]


def schedule_active_scans(enqueue, *, limit: int = 100, cooldown: ScanCooldown | None = None, now=None) -> dict[str, int]:
    if limit < 1:
        raise ValueError("scan schedule limit must be positive")
    policy = cooldown or ScanCooldown(0)
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    current_naive = current.astimezone(timezone.utc).replace(tzinfo=None)
    with get_session() as session:
        images = session.query(Image).filter(Image.active.is_(True)).order_by(Image.id.asc()).all()[:limit]
        image_ids = [image.id for image in images if getattr(image, "id", None) is not None]
        schedules = session.query(ScanSchedule).filter(ScanSchedule.image_id.in_(image_ids)).all() if image_ids else []
        schedule_by_image = {schedule.image_id: schedule for schedule in schedules if getattr(schedule, "image_id", None) is not None}
        due: list[tuple[str, int | None, int | None]] = []
        for image in images:
            schedule = schedule_by_image.get(getattr(image, "id", None))
            if schedule is not None:
                next_run_at = getattr(schedule, "next_run_at", None)
                if next_run_at is not None and next_run_at.tzinfo is not None:
                    next_run_at = next_run_at.astimezone(timezone.utc).replace(tzinfo=None)
                if not getattr(schedule, "enabled", False) or (next_run_at is not None and next_run_at > current_naive):
                    continue
                due.append((image.full_name, schedule.id, schedule.interval_seconds))
            elif not cooldown_active(getattr(image, "last_scan_at", None), policy=policy, now=current):
                due.append((image.full_name, None, None))
    for image_name, schedule_id, interval_seconds in due:
        enqueue(image_name, priority="low")
        if schedule_id is not None:
            with get_session() as session:
                schedule = session.get(ScanSchedule, schedule_id)
                if schedule is not None:
                    schedule.last_queued_at = current_naive
                    schedule.next_run_at = current_naive + timedelta(seconds=interval_seconds or 21600)
    set_queue_health("scan.low", len(due), 0)
    return {"discovered": len(images), "queued": len(due), "suppressed": len(images) - len(due)}
