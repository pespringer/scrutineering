"""The one place that turns a scan target into durable image and scan records.

Every caller (dashboard, retry, scheduler, runtime discovery, post-merge
verification) creates its pending scan here before queueing work, so scans are
visible from the moment they are requested and the worker never has to guess
which image a scan belongs to.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from src.db.models import Image, Scan, ScanStatus
from src.scan.image_identity import ImageIdentity, parse_image_reference
from src.scan.source_target import storage_reference


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def scan_identity(target: str) -> ImageIdentity:
    """Identity for an image reference or an `fs:<path>` filesystem target."""
    return parse_image_reference(storage_reference(target))


def get_or_create_image(session: Session, identity: ImageIdentity) -> Image:
    image = session.query(Image).filter_by(
        registry_name=identity.registry, repo_name=identity.repo_name, tag=identity.tag,
    ).first()
    if image is None:
        image = Image(
            registry_name=identity.registry, repo_name=identity.repo_name,
            tag=identity.tag, digest=identity.digest,
        )
        session.add(image)
        session.flush()
    elif identity.digest:
        image.digest = identity.digest
    if not image.active:
        image.active = True
    return image


def create_pending_scan(
    session: Session, target: str, *, scan_id: str | None = None, trigger: str = "manual",
) -> Scan:
    """Create (or return the existing) pending scan for `target`."""
    scan_id = scan_id or uuid.uuid4().hex
    existing = session.query(Scan).filter_by(scan_id=scan_id).first()
    if existing is not None:
        return existing
    identity = scan_identity(target)
    image = get_or_create_image(session, identity)
    scan = Scan(
        scan_id=scan_id, image_id=image.id, target=target, status=ScanStatus.PENDING.value,
        phase="queued", task_id=scan_id, started_at=_now(), image_digest=identity.digest,
        scheduler_type=trigger,
    )
    session.add(scan)
    image.last_scan_id = scan_id
    session.flush()
    return scan


def mark_scan_failed(session: Session, scan_id: str, reason: str, *, phase: str = "failed") -> Scan | None:
    """Move a scan to `failed` unless it already reached a terminal state."""
    scan = session.query(Scan).filter_by(scan_id=scan_id).first()
    if scan is None:
        return None
    if scan.status in {ScanStatus.COMPLETED, ScanStatus.PARTIAL, ScanStatus.FAILED, ScanStatus.CANCELLED}:
        return scan
    now = _now()
    scan.status = ScanStatus.FAILED.value
    scan.phase = phase
    scan.error_message = reason[:2000]
    scan.completed_at = now
    if scan.image is not None:
        scan.image.last_scan_at = now
    return scan


def queue_scan(target: str, *, priority: str = "normal", scan_id: str | None = None, trigger: str = "manual",
               session_factory=None, enqueue=None) -> str:
    """Create the pending scan, commit it, hand it to the queue, and return its ID.

    If the queue rejects the task, the scan is marked failed instead of being
    left pending forever.
    """
    if session_factory is None:
        from src.db.connection import get_session as session_factory
    if enqueue is None:
        from src.scan.tasks import enqueue_scan as enqueue
    with session_factory() as session:
        scan = create_pending_scan(session, target, scan_id=scan_id, trigger=trigger)
        scan_id = scan.scan_id
    try:
        enqueue(target, priority=priority, scan_id=scan_id)
    except Exception as exc:
        with session_factory() as session:
            mark_scan_failed(session, scan_id, f"scan queue unavailable: {exc}", phase="queue_failed")
        raise
    return scan_id
