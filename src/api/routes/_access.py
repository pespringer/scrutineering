"""Operator audit events and shared query parsing for dashboard routes."""

from __future__ import annotations


from fastapi import HTTPException, Request

from src.db.models import (
    AuditEventType,
    Severity,
)
from src.db.repositories import AuditLogRepository


def severity_filter(value: str | None) -> Severity | None:
    if not value or value.lower() == "all":
        return None
    try:
        return Severity(value.lower())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="invalid severity") from exc


def _with_email(detail: dict, email: str | None) -> dict:
    """Signed-in users are recorded by their proxy's user ID; the email keeps the trail readable."""
    return {**detail, "actor_email": email} if email else detail


def record_operator_event(
    session, request: Request, event_type: AuditEventType, entity_id: str, detail: dict, entity_type: str = "scan"
) -> None:
    AuditLogRepository.record(
        session,
        event_type=event_type,
        entity_type=entity_type,
        entity_id=entity_id,
        detail=_with_email(detail, getattr(request.state, "principal_email", None)),
        actor=getattr(request.state, "principal_id", "dashboard-service"),
        actor_kind="user" if getattr(request.state, "auth_method", "") == "oidc_proxy" else "system",
    )
