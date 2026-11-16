"""Audit trail and audit export."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime

from fastapi import APIRouter, Query, Request

from src.db.connection import get_session
from src.db.models import (
    AuditLog,
)
from src.api.serializers import (
    enum_value, iso, paginate,
)
from src.api.routes._access import require_role

router = APIRouter()


@router.get("/audit")
def dashboard_audit(
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    actor: str | None = Query(default=None, max_length=128),
    event_type: str | None = Query(default=None, max_length=64),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
) -> dict:
    with get_session() as session:
        query = session.query(AuditLog)
        if actor:
            query = query.filter(AuditLog.actor == actor)
        if event_type:
            query = query.filter(AuditLog.event_type == event_type.lower())
        if since:
            query = query.filter(AuditLog.timestamp >= since.replace(tzinfo=None))
        if until:
            query = query.filter(AuditLog.timestamp <= until.replace(tzinfo=None))
        total = query.order_by(None).count()
        records = query.order_by(AuditLog.timestamp.desc(), AuditLog.id.desc()).offset(offset).limit(limit).all()
    items = [{
        "id": record.id,
        "timestamp": iso(record.timestamp),
        "event_type": enum_value(record.event_type),
        "entity_type": record.entity_type,
        "entity_id": record.entity_id,
        "detail": record.detail,
        "actor": record.actor,
        "actor_kind": record.actor_kind,
    } for record in records]
    return paginate(items, limit, offset, total)


@router.get("/audit/export")
def dashboard_audit_export(request: Request, limit: int = Query(default=1000, ge=1, le=5000), actor: str | None = Query(default=None), event_type: str | None = Query(default=None), since: datetime | None = Query(default=None), until: datetime | None = Query(default=None)) -> dict:
    require_role(request, "security-operator", "admin")
    with get_session() as session:
        query = session.query(AuditLog)
        if actor: query = query.filter(AuditLog.actor == actor)
        if event_type: query = query.filter(AuditLog.event_type == event_type.lower())
        if since: query = query.filter(AuditLog.timestamp >= since.replace(tzinfo=None))
        if until: query = query.filter(AuditLog.timestamp <= until.replace(tzinfo=None))
        records = query.order_by(AuditLog.timestamp.asc(), AuditLog.id.asc()).limit(limit).all()
    items = [{"id": record.id, "timestamp": iso(record.timestamp), "event_type": enum_value(record.event_type), "entity_type": record.entity_type, "entity_id": record.entity_id, "detail": record.detail, "actor": record.actor, "actor_kind": record.actor_kind, "record_hash": record.record_hash, "previous_hash": record.previous_hash} for record in records]
    canonical = json.dumps(items, sort_keys=True, separators=(",", ":")).encode()
    return {"format": "scrutineering-audit-v1", "count": len(items), "sha256": hashlib.sha256(canonical).hexdigest(), "records": items}
