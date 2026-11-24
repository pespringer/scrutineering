"""Data access layer (repositories) for Container Sentinel.

Each repository wraps a model and provides typed CRUD operations.
All methods accept a SQLAlchemy Session passed in by the caller so
transactions can span multiple repositories.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Sequence

from sqlalchemy import func, select, text, update
from sqlalchemy.orm import Session, joinedload

from src.db import audit_chain
from src.db.models import (
    AuditLog,
    AuditEventType,
    Remediation,
    RemediationAction,
    RemediationEvent,
    RemediationStatus,
)
from src.notifications import outbox as notifications
from src.remediation.state_machine import TERMINAL, transition


def _utcnow() -> datetime:
    """Naive UTC with microseconds, as scans stamp theirs. On SQLite `func.now()` is whole seconds, which
    would put a remediation and the scan that completed it out of order within the same second."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class RemediationRepository:
    """CRUD for remediation workflows."""

    @staticmethod
    def create(
        session: Session,
        image_id: int,
        scan_id: str | None = None,
        finding_count: int = 0,
        target_severities: dict | None = None,
    ) -> Remediation:
        rem = Remediation(
            image_id=image_id,
            scan_id=scan_id,
            finding_count=finding_count,
            target_severities=target_severities or {},
            created_at=_utcnow(),
        )
        session.add(rem)
        session.flush()
        return rem

    @staticmethod
    def update_status(
        session: Session,
        remediation_id: int,
        status,  # RemediationStatus enum value
        **kw,
    ) -> None:
        current = session.execute(
            select(Remediation.status).where(Remediation.id == remediation_id)
        ).scalar_one_or_none()
        if current is None:
            raise ValueError(f"Remediation {remediation_id} does not exist")

        current_status = RemediationStatus(current)
        target_status = RemediationStatus(status)
        transition(current_status, target_status)

        values: dict = {"status": target_status}
        if target_status == RemediationStatus.BUILDING and "started_at" not in kw:
            values["started_at"] = _utcnow()
        if target_status in TERMINAL:
            values["completed_at"] = _utcnow()
        values.update({k: v for k, v in kw.items() if k in values or k not in ("status",)})
        session.execute(
            update(Remediation)
            .where(Remediation.id == remediation_id)
            .values(**{k: v for k, v in values.items() if v is not None})
        )
        if target_status != current_status:
            notifications.record(session, remediation_id, target_status)

    @staticmethod
    def add_action(
        session: Session,
        remediation_id: int,
        action_type,
        file_path: str | None = None,
        before_value: str | None = None,
        after_value: str | None = None,
        success: bool = False,
        detail: dict | None = None,
    ) -> RemediationAction:
        action = RemediationAction(
            remediation_id=remediation_id,
            action_type=action_type,
            file_path=file_path,
            before_value=before_value,
            after_value=after_value,
            success=success,
            detail=detail or {},
        )
        session.add(action)
        session.flush()
        return action

    @staticmethod
    def get_by_id(session: Session, remediation_id: int) -> Remediation | None:
        return (
            session.execute(
                select(Remediation).options(joinedload(Remediation.actions)).where(Remediation.id == remediation_id)
            )
            .unique()
            .scalar_one_or_none()
        )

    @staticmethod
    def append_event(session: Session, event: dict) -> RemediationEvent:
        """Persist one ordered lifecycle event for restart recovery."""
        record = RemediationEvent(
            remediation_id=int(event["remediation_id"]),
            event_type=str(event["event_type"]),
            sequence=int(event["sequence"]),
            detail=dict(event.get("detail") or {}),
        )
        session.add(record)
        session.flush()
        return record

    @staticmethod
    def record_event(session: Session, remediation_id: int, event_type: str, detail: dict | None = None):
        """Append the next event in sequence. History only: never read back to decide current state."""
        sequence = (
            session.execute(
                select(func.max(RemediationEvent.sequence)).where(RemediationEvent.remediation_id == remediation_id)
            ).scalar()
            or 0
        )
        return RemediationRepository.append_event(
            session,
            {"remediation_id": remediation_id, "event_type": event_type, "sequence": sequence + 1, "detail": detail},
        )

    @staticmethod
    def list_events(session: Session, remediation_id: int) -> Sequence[RemediationEvent]:
        return (
            session.execute(
                select(RemediationEvent)
                .where(RemediationEvent.remediation_id == remediation_id)
                .order_by(RemediationEvent.sequence, RemediationEvent.id)
            )
            .scalars()
            .all()
        )


class AuditLogRepository:
    """Append-only audit log writes."""

    @staticmethod
    def record(
        session: Session,
        event_type: AuditEventType,
        detail: dict | None = None,
        entity_type: str | None = None,
        entity_id: str | None = None,
        image_id: int | None = None,
        actor: str | None = None,
        actor_kind: str | None = None,
    ) -> AuditLog:
        if session.get_bind().dialect.name == "postgresql":
            # Held until this transaction commits, so no other writer can read the same head (no fork).
            session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": audit_chain.LOCK_KEY})
        previous = session.execute(select(AuditLog.record_hash).order_by(AuditLog.id.desc()).limit(1)).scalar()
        entry = AuditLog(
            timestamp=_utcnow(),
            event_type=event_type,
            detail=detail or {},
            entity_type=entity_type,
            entity_id=entity_id,
            image_id=image_id,
            actor=actor,
            actor_kind=actor_kind,
            previous_hash=previous or "",
        )
        entry.record_hash = audit_chain.hash_of(entry, entry.previous_hash)
        session.add(entry)
        session.flush()
        return entry
