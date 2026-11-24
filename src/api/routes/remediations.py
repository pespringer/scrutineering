"""Remediation previews, proposals and the queue; the steps after proposal are in remediation_steps."""

from __future__ import annotations

from collections import Counter

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
from src.notifications import outbox as notifications
from src.remediation.planner import Plan, finding_input
from src.remediation.planner import plan as plan_fixes
from src.remediation.sources import snapshot
from src.scan.deployments import remediation_deployment
from src.api.routes.evidence import evidence_summary, latest_bundle
from src.api.schemas import RemediationRequest
from src.api.serializers import (
    enum_value,
    image_payload,
    iso,
    paginate,
    remediation_payload,
)
from src.api.routes._access import record_operator_event
from src.api.roles import require_action
from src.api.routes.remediation_steps import request_actor

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
    require_action(request, "remediations.propose")
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
    require_action(request, "remediations.view")
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
    require_action(request, "remediations.propose")
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
        remediation.proposed_by = request_actor(request)
        remediation.source = snapshot(image.source)
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
        notifications.record(session, remediation.id, RemediationStatus.PROPOSED)  # creation skips update_status
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
    require_action(request, "remediations.view")
    with get_session() as session:
        remediation = RemediationRepository.get_by_id(session, remediation_id)
        if remediation is None:
            raise HTTPException(status_code=404, detail="remediation_not_found")
        return {
            **remediation_payload(remediation),
            "evidence": evidence_summary(latest_bundle(session, remediation_id)),
            "deployment": remediation_deployment(session, remediation),
        }


@router.get("/remediations/{remediation_id}/events")
def remediation_events(remediation_id: int, request: Request) -> dict:
    require_action(request, "remediations.view")
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
