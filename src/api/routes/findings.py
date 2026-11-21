"""Bulk finding actions and finding export."""

from __future__ import annotations

import hashlib
import json

from fastapi import APIRouter, Query, Request

from src.db.connection import get_session
from src.db.models import (
    AuditEventType,
    ScanFinding,
)
from src.api.schemas import BulkFindingAssignmentRequest, BulkIdsRequest
from src.api.serializers import (
    finding_payload,
)
from src.api.routes._access import record_operator_event, severity_filter
from src.api.roles import require_action

router = APIRouter()


@router.post("/findings/bulk-acknowledge")
def bulk_acknowledge_findings(payload: BulkIdsRequest, request: Request) -> dict:
    require_action(request, "findings.triage")
    finding_ids = [int(value) for value in payload.ids]
    changed: list[int] = []
    with get_session() as session:
        for finding in (
            session.query(ScanFinding).filter(ScanFinding.id.in_(finding_ids), ScanFinding.resolved_at.is_(None)).all()
        ):
            finding.acknowledged = True
            changed.append(finding.id)
        if changed:
            record_operator_event(
                session,
                request,
                AuditEventType.CONFIG_CHANGED,
                ",".join(map(str, changed)),
                {"action": "acknowledge_findings", "finding_ids": changed},
                entity_type="finding",
            )
    return {"requested": finding_ids, "acknowledged": changed, "count": len(changed)}


@router.post("/findings/bulk-assign")
def bulk_assign_findings(payload: BulkFindingAssignmentRequest, request: Request) -> dict:
    require_action(request, "findings.triage")
    changed: list[int] = []
    with get_session() as session:
        for finding in (
            session.query(ScanFinding)
            .filter(ScanFinding.id.in_(payload.finding_ids), ScanFinding.resolved_at.is_(None))
            .all()
        ):
            finding.assigned_to = payload.assignee
            changed.append(finding.id)
        if changed:
            record_operator_event(
                session,
                request,
                AuditEventType.CONFIG_CHANGED,
                ",".join(map(str, changed)),
                {"action": "assign_findings", "finding_ids": changed, "assignee": payload.assignee},
                entity_type="finding",
            )
    return {"requested": payload.finding_ids, "assigned": changed, "assignee": payload.assignee, "count": len(changed)}


@router.get("/findings/export")
def export_findings(
    request: Request,
    limit: int = Query(default=1000, ge=1, le=5000),
    severity: str | None = Query(default=None),
    image_id: int | None = Query(default=None),
    acknowledged: bool | None = Query(default=None),
) -> dict:
    require_action(request, "findings.export")
    severity_value = severity_filter(severity)
    with get_session() as session:
        query = session.query(ScanFinding).filter(ScanFinding.resolved_at.is_(None))
        if severity_value:
            query = query.filter(ScanFinding.severity == severity_value.value)
        if image_id:
            query = query.filter(ScanFinding.image_id == image_id)
        if acknowledged is not None:
            query = query.filter(ScanFinding.acknowledged.is_(acknowledged))
        findings = query.order_by(ScanFinding.id.asc()).limit(limit).all()
    records = [finding_payload(finding) for finding in findings]
    canonical = json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
    return {
        "format": "scrutineering-findings-v1",
        "count": len(records),
        "sha256": hashlib.sha256(canonical).hexdigest(),
        "records": records,
    }
