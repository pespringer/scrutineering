"""Remediation proposals, approval, execution, and retry."""

from __future__ import annotations

import os
from collections import Counter
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query, Request

from src.db.connection import get_session
from src.db.models import (
    AuditEventType,
    Image,
    Remediation,
    RemediationActionType,
    RemediationStatus,
    ScanFinding,
)
from src.db.repositories import RemediationRepository
from src.remediation.planner import Plan, finding_input
from src.remediation.state_machine import TRANSITIONS
from src.remediation.planner import plan as plan_fixes
from src.remediation.worker import execute_approved_remediation
from src.api.schemas import RemediationRequest
from src.api.serializers import (
    enum_value,
    image_payload,
    iso,
    paginate,
    remediation_payload,
)
from src.api.routes._access import record_operator_event, require_role

router = APIRouter()


ACTION_TYPES = {
    "dependency_update": RemediationActionType.DEPENDENCY_UPDATE,
    "os_package_upgrade": RemediationActionType.OS_PACKAGE_UPGRADE,
    "base_image_bump": RemediationActionType.BASE_IMAGE_BUMP,
}


def _plan(findings: list[ScanFinding]) -> Plan:
    return plan_fixes([finding_input(finding) for finding in findings])


def _plan_payload(image: Image, findings: list[ScanFinding]) -> dict:
    plan = _plan(findings)
    source_connected = image.source is not None
    actionable_ids = sorted(plan.actionable_finding_ids) if source_connected else []
    return {
        "image": image_payload(image, findings),
        "source_connected": source_connected,
        "finding_ids": [finding.id for finding in findings],
        "actions": [{**action.as_dict(), "safe_to_apply": source_connected} for action in plan.actions],
        "manual": [{"finding_id": item.finding_id, "reason": item.reason} for item in plan.manual],
        "actionable_finding_ids": actionable_ids,
        "actionable_count": len(actionable_ids),
        "requires_approval": True,
        "mutates_state": False,
    }


@router.post("/remediations/preview")
def remediation_preview(payload: RemediationRequest, request: Request) -> dict:
    """How the selected findings would be fixed. Changes nothing."""
    require_role(request, "remediator", "security-operator")
    with get_session() as session:
        image = session.get(Image, payload.image_id)
        if image is None:
            raise HTTPException(status_code=404, detail="image_not_found")
        findings = (
            session.query(ScanFinding)
            .filter(
                ScanFinding.image_id == payload.image_id,
                ScanFinding.id.in_(payload.finding_ids),
                ScanFinding.resolved_at.is_(None),
            )
            .order_by(ScanFinding.severity.asc(), ScanFinding.id.asc())
            .all()
        )
        if len(findings) != len(set(payload.finding_ids)):
            raise HTTPException(status_code=400, detail="findings_must_belong_to_image")
        return _plan_payload(image, findings)


@router.get("/remediations")
def list_remediations(
    request: Request,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    status: str | None = Query(default=None, max_length=32),
) -> dict:
    require_role(request, "remediator", "security-operator")
    with get_session() as session:
        query = session.query(Remediation)
        if status:
            try:
                query = query.filter(Remediation.status == RemediationStatus(status.lower()))
            except ValueError as exc:
                raise HTTPException(status_code=400, detail="invalid_remediation_status") from exc
        total = query.order_by(None).count()
        records = query.order_by(Remediation.created_at.desc(), Remediation.id.desc()).offset(offset).limit(limit).all()
        items = [remediation_payload(record) for record in records]
    return paginate(items, limit, offset, total)


@router.post("/remediations", status_code=201)
def create_remediation(payload: RemediationRequest, request: Request) -> dict:
    require_role(request, "remediator", "security-operator")
    requested_ids = set(payload.finding_ids)
    if len(requested_ids) != len(payload.finding_ids):
        raise HTTPException(status_code=400, detail="finding_ids_must_be_unique")
    with get_session() as session:
        image = session.get(Image, payload.image_id)
        requested_findings = (
            session.query(ScanFinding)
            .filter(
                ScanFinding.image_id == payload.image_id,
                ScanFinding.id.in_(requested_ids),
            )
            .all()
        )
        # A completed remediation no longer holds its findings: if one reopens, it can be fixed again.
        already_owned = {
            finding.id: finding.remediation_id
            for finding in requested_findings
            if finding.remediation is not None and finding.remediation.status != RemediationStatus.COMPLETED
        }
        if already_owned:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "finding_already_in_remediation",
                    "finding_ids": sorted(already_owned),
                    "remediation_ids": sorted({value for value in already_owned.values() if value is not None}),
                },
            )
        if image is None:
            raise HTTPException(status_code=404, detail="image_not_found")
        if image.source is None:
            raise HTTPException(
                status_code=409,
                detail={"code": "source_not_connected", "reason": "Connect the image's source repository first."},
            )
        findings = (
            session.query(ScanFinding)
            .filter(
                ScanFinding.image_id == payload.image_id,
                ScanFinding.id.in_(requested_ids),
                ScanFinding.resolved_at.is_(None),
            )
            .all()
        )
        if len(findings) != len(requested_ids):
            raise HTTPException(status_code=400, detail="findings_must_be_open_and_belong_to_image")
        plan = _plan(findings)
        if plan.manual:
            raise HTTPException(
                status_code=400,
                detail={
                    "code": "findings_not_actionable",
                    "findings": [{"finding_id": item.finding_id, "reason": item.reason} for item in plan.manual],
                },
            )
        severities = Counter(enum_value(finding.severity) or "unknown" for finding in findings)
        remediation = RemediationRepository.create(
            session,
            image_id=image.id,
            finding_count=len(findings),
            target_severities=dict(severities),
        )
        remediation.status = RemediationStatus.PROPOSED
        for finding in findings:
            finding.remediation_id = remediation.id
        for action in plan.actions:
            detail = action.as_dict()
            RemediationRepository.add_action(
                session,
                remediation.id,
                ACTION_TYPES[action.strategy],
                before_value=action.from_version,
                after_value=action.to_version,
                detail=detail,
            )
        record_operator_event(
            session,
            request,
            AuditEventType.REMEDIATION_STARTED,
            str(remediation.id),
            {"action": "remediation_requested", "finding_ids": payload.finding_ids},
            entity_type="remediation",
        )
        session.flush()
        session.refresh(remediation)
        return remediation_payload(remediation)


@router.get("/remediations/{remediation_id}")
def remediation_detail(remediation_id: int, request: Request) -> dict:
    require_role(request, "remediator", "security-operator")
    with get_session() as session:
        remediation = RemediationRepository.get_by_id(session, remediation_id)
        if remediation is None:
            raise HTTPException(status_code=404, detail="remediation_not_found")
        return remediation_payload(remediation)


@router.get("/remediations/{remediation_id}/events")
def remediation_events(remediation_id: int, request: Request) -> dict:
    require_role(request, "remediator", "security-operator")
    with get_session() as session:
        if session.get(Remediation, remediation_id) is None:
            raise HTTPException(status_code=404, detail="remediation_not_found")
        events = RemediationRepository.list_events(session, remediation_id)
    return {
        "remediation_id": remediation_id,
        "latest_event": (
            {
                "event_type": events[-1].event_type,
                "detail": events[-1].detail,
                "created_at": iso(events[-1].created_at),
            }
            if events
            else None
        ),
        "events": [
            {
                "id": event.id,
                "event_type": event.event_type,
                "sequence": event.sequence,
                "detail": event.detail,
                "created_at": iso(event.created_at),
            }
            for event in events
        ],
    }


def _load(session, remediation_id: int) -> Remediation:
    remediation = session.get(Remediation, remediation_id)
    if remediation is None:
        raise HTTPException(status_code=404, detail="remediation_not_found")
    return remediation


def _require_status(remediation: Remediation, *allowed: RemediationStatus) -> None:
    if remediation.status not in allowed:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "invalid_remediation_status",
                "status": enum_value(remediation.status),
                "allowed": [status.value for status in allowed],
            },
        )


def _actor(request: Request) -> str:
    return getattr(request.state, "principal_id", "dashboard-service")


def _audit(session, request: Request, remediation_id: int, action: str, **detail) -> None:
    record_operator_event(
        session,
        request,
        AuditEventType.CONFIG_CHANGED,
        str(remediation_id),
        {"action": action, **detail},
        entity_type="remediation",
    )


@router.post("/remediations/{remediation_id}/approve")
def approve_remediation(remediation_id: int, request: Request) -> dict:
    """Approve a proposed remediation for execution. Requires the security-operator role."""
    require_role(request, "security-operator")
    approver = _actor(request)
    with get_session() as session:
        _require_status(_load(session, remediation_id), RemediationStatus.PROPOSED)
        RemediationRepository.update_status(
            session,
            remediation_id,
            RemediationStatus.APPROVED,
            approved_by=approver,
            approved_at=datetime.now(timezone.utc).replace(tzinfo=None),
        )
        RemediationRepository.record_event(session, remediation_id, "approved", {"approver": approver})
        _audit(session, request, remediation_id, "remediation_approved", approver=approver)
        return remediation_payload(RemediationRepository.get_by_id(session, remediation_id))


@router.post("/remediations/{remediation_id}/execute", status_code=202)
def execute_remediation(remediation_id: int, request: Request) -> dict:
    """Start building and verifying the patched image. The status moves to `building` before the task is queued."""
    require_role(request, "remediator", "security-operator")
    if os.environ.get("REMEDIATION_EXECUTION_ENABLED", "false").lower() not in {"1", "true", "yes"}:
        raise HTTPException(status_code=503, detail="remediation_execution_disabled")
    with get_session() as session:
        _require_status(_load(session, remediation_id), RemediationStatus.APPROVED)
        RemediationRepository.update_status(session, remediation_id, RemediationStatus.BUILDING, error_message=None)
        RemediationRepository.record_event(session, remediation_id, "execution_queued", {"by": _actor(request)})
    # Dispatch after the status commit so the worker always sees `building`.
    task = execute_approved_remediation.apply_async(args=[remediation_id], queue="remediation.normal")
    with get_session() as session:
        _audit(session, request, remediation_id, "remediation_execution_requested", task_id=task.id)
    return {"remediation_id": remediation_id, "task_id": task.id, "status": RemediationStatus.BUILDING.value}


@router.post("/remediations/{remediation_id}/accept")
def accept_remediation(remediation_id: int, request: Request) -> dict:
    """Accept a verified candidate that introduced new critical/high findings (decision D6)."""
    require_role(request, "security-operator")
    with get_session() as session:
        _require_status(_load(session, remediation_id), RemediationStatus.NEEDS_ACCEPTANCE)
        RemediationRepository.update_status(session, remediation_id, RemediationStatus.READY)
        RemediationRepository.record_event(session, remediation_id, "accepted", {"by": _actor(request)})
        _audit(session, request, remediation_id, "remediation_new_findings_accepted")
        return remediation_payload(RemediationRepository.get_by_id(session, remediation_id))


@router.post("/remediations/{remediation_id}/retry")
def retry_remediation(remediation_id: int, request: Request) -> dict:
    """Return a failed remediation to approval so an operator can deliberately restart it."""
    require_role(request, "security-operator")
    with get_session() as session:
        _require_status(_load(session, remediation_id), RemediationStatus.FAILED)
        RemediationRepository.update_status(session, remediation_id, RemediationStatus.PROPOSED)
        remediation = session.get(Remediation, remediation_id)
        remediation.error_message = None
        remediation.approved_by = None
        remediation.approved_at = None
        RemediationRepository.record_event(session, remediation_id, "retry_requested", {"by": _actor(request)})
        _audit(session, request, remediation_id, "remediation_retry_requested")
        return remediation_payload(RemediationRepository.get_by_id(session, remediation_id))


@router.post("/remediations/{remediation_id}/cancel")
def cancel_remediation(remediation_id: int, request: Request) -> dict:
    """Stop a remediation and release its findings so they can be proposed again."""
    require_role(request, "remediator", "security-operator")
    with get_session() as session:
        remediation = _load(session, remediation_id)
        _require_status(
            remediation, *(status for status in RemediationStatus if RemediationStatus.CANCELLED in TRANSITIONS[status])
        )
        RemediationRepository.update_status(session, remediation_id, RemediationStatus.CANCELLED)
        for finding in session.query(ScanFinding).filter(ScanFinding.remediation_id == remediation_id):
            finding.remediation_id = None
        RemediationRepository.record_event(session, remediation_id, "cancelled", {"by": _actor(request)})
        _audit(session, request, remediation_id, "remediation_cancelled")
        return remediation_payload(RemediationRepository.get_by_id(session, remediation_id))
