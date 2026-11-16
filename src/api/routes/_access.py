"""Role checks, operator audit events, and shared query parsing for dashboard routes."""

from __future__ import annotations


from fastapi import HTTPException, Request

from src.db.models import (
    AuditEventType, Severity,
)
from src.db.repositories import AuditLogRepository


def severity_filter(value: str | None) -> Severity | None:
    if not value or value.lower() == "all":
        return None
    try:
        return Severity(value.lower())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="invalid severity") from exc


def require_role(request: Request, *allowed: str) -> None:
    roles = set(getattr(request.state, "principal_roles", []))
    if not roles.intersection({*allowed, "admin"}):
        raise HTTPException(status_code=403, detail="operator_role_required")


def record_operator_event(session, request: Request, event_type: AuditEventType, entity_id: str, detail: dict, entity_type: str = "scan") -> None:
    AuditLogRepository.record(
        session,
        event_type=event_type,
        entity_type=entity_type,
        entity_id=entity_id,
        detail=detail,
        actor=getattr(request.state, "principal_id", "dashboard-service"),
        actor_kind="user" if getattr(request.state, "auth_method", "") == "oidc_proxy" else "system",
    )
