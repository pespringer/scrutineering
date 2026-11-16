"""Remediation proposals, approval, execution, and retry."""

from __future__ import annotations

import os
from collections import Counter
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query, Request

from src.db.connection import get_session
from src.db.models import (
    AuditEventType, Image, Remediation, RemediationActionType,
    RemediationStatus, ScanFinding,
)
from src.db.repositories import RemediationRepository
from src.remediation.worker import execute_approved_remediation
from src.api.schemas import RemediationRequest
from src.api.serializers import (
    enum_value, image_payload, iso, paginate, remediation_payload,
)
from src.api.routes._access import record_operator_event, require_role

router = APIRouter()


def _remediation_file_path(finding: ScanFinding, image: Image | None = None) -> str | None:
    file_path = getattr(finding, "file_path", None)
    if not file_path or image is None:
        return file_path
    repository_name = str(getattr(image, "repo_name", ""))
    if getattr(image, "tag", None) == "filesystem" and repository_name.startswith("local/"):
        source_directory = repository_name.removeprefix("local/")
        if source_directory and not file_path.startswith(f"{source_directory}/"):
            return f"{source_directory}/{file_path}"
    return file_path


def _remediation_actions(findings: list[ScanFinding], image: Image | None = None) -> list[dict]:
    return [{
        "finding_id": finding.id,
        "action_type": RemediationActionType.DEPENDENCY_UPDATE.value,
        "package_name": finding.package_name,
        "from_version": finding.package_version,
        "to_version": finding.fixed_version,
        "file_path": _remediation_file_path(finding, image),
        "cve_id": finding.cve_id,
        "severity": enum_value(finding.severity),
        "safe_to_apply": bool(finding.fix_available and finding.fixed_version and _remediation_file_path(finding, image)),
    } for finding in findings]


def _unsafe_remediation_actions(actions: list[dict]) -> list[dict]:
    return [action for action in actions if not action["safe_to_apply"]]


@router.post("/remediations/preview")
def remediation_preview(payload: RemediationRequest, request: Request) -> dict:
    require_role(request, "remediator", "security-operator")
    with get_session() as session:
        image = session.get(Image, payload.image_id)
        findings = session.query(ScanFinding).filter(
            ScanFinding.image_id == payload.image_id,
            ScanFinding.id.in_(payload.finding_ids),
            ScanFinding.resolved_at.is_(None),
        ).order_by(ScanFinding.severity.asc(), ScanFinding.id.asc()).all()
    if image is None:
        raise HTTPException(status_code=404, detail="image_not_found")
    if len(findings) != len(set(payload.finding_ids)):
        raise HTTPException(status_code=400, detail="findings_must_belong_to_image")
    actions = _remediation_actions(findings, image)
    return {
        "image": image_payload(image, findings),
        "finding_ids": [finding.id for finding in findings],
        "actions": actions,
        "actionable_count": sum(action["safe_to_apply"] for action in actions),
        "requires_approval": True,
        "mutates_state": False,
    }


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
        requested_findings = session.query(ScanFinding).filter(
            ScanFinding.image_id == payload.image_id,
            ScanFinding.id.in_(requested_ids),
        ).all()
        already_owned = {
            finding.id: finding.remediation_id
            for finding in requested_findings
            if finding.remediation_id is not None
        }
        if already_owned:
            raise HTTPException(status_code=409, detail={
                "code": "finding_already_in_remediation",
                "finding_ids": sorted(already_owned),
                "remediation_ids": sorted({value for value in already_owned.values() if value is not None}),
            })
        findings = session.query(ScanFinding).filter(
            ScanFinding.image_id == payload.image_id,
            ScanFinding.id.in_(requested_ids),
            ScanFinding.resolved_at.is_(None),
            ScanFinding.fix_available.is_(True),
        ).all()
        if image is None:
            raise HTTPException(status_code=404, detail="image_not_found")
        if len(findings) != len(set(payload.finding_ids)):
            raise HTTPException(status_code=400, detail="all_findings_need_available_fixes")
        actions = _remediation_actions(findings, image)
        unsafe_actions = _unsafe_remediation_actions(actions)
        if unsafe_actions:
            raise HTTPException(status_code=400, detail={
                "code": "findings_not_actionable",
                "finding_ids": [action["finding_id"] for action in unsafe_actions],
                "reason": "Each remediation action requires a fixed version and explicit source file path.",
            })
        severities = Counter(enum_value(finding.severity) or "unknown" for finding in findings)
        remediation = RemediationRepository.create(
            session,
            image_id=image.id,
            finding_count=len(findings),
            target_severities=dict(severities),
        )
        remediation.status = RemediationStatus.REQUIRES_REVIEW
        for finding, action in zip(findings, actions):
            finding.remediation_id = remediation.id
            RemediationRepository.add_action(
                session, remediation.id, RemediationActionType.DEPENDENCY_UPDATE,
                file_path=_remediation_file_path(finding, image),
                before_value=finding.package_version, after_value=finding.fixed_version,
                detail={"finding_id": finding.id, "package_name": finding.package_name, "cve_id": finding.cve_id, "file_path": _remediation_file_path(finding, image)},
            )
        record_operator_event(session, request, AuditEventType.REMEDIATION_STARTED, str(remediation.id), {"action": "remediation_requested", "finding_ids": payload.finding_ids}, entity_type="remediation")
        return remediation_payload(remediation, actions)


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
    return {"remediation_id": remediation_id, "latest_event": ({
        "event_type": events[-1].event_type,
        "detail": events[-1].detail,
        "created_at": iso(events[-1].created_at),
    } if events else None), "events": [{
        "id": event.id, "event_type": event.event_type, "sequence": event.sequence,
        "detail": event.detail, "created_at": iso(event.created_at),
    } for event in events]}


@router.post("/remediations/{remediation_id}/approve")
def approve_remediation(remediation_id: int, request: Request) -> dict:
    """Approve a proposed remediation for execution. Requires the security-operator role."""
    require_role(request, "security-operator")
    approver = getattr(request.state, "principal_id", "dashboard-service")
    with get_session() as session:
        remediation = session.get(Remediation, remediation_id)
        if remediation is None:
            raise HTTPException(status_code=404, detail="remediation_not_found")
        if enum_value(remediation.status) != RemediationStatus.REQUIRES_REVIEW.value:
            raise HTTPException(status_code=409, detail="remediation_not_awaiting_approval")
        RemediationRepository.update_status(
            session, remediation_id, RemediationStatus.ANALYZING,
            approved_by=approver, approved_at=datetime.now(timezone.utc).replace(tzinfo=None),
        )
        record_operator_event(
            session, request, AuditEventType.CONFIG_CHANGED, str(remediation_id),
            {"action": "remediation_approved", "approver": approver}, entity_type="remediation",
        )
        remediation = RemediationRepository.get_by_id(session, remediation_id)
        return remediation_payload(remediation)


@router.post("/remediations/{remediation_id}/execute", status_code=202)
def execute_remediation(remediation_id: int, request: Request) -> dict:
    require_role(request, "remediator", "security-operator")
    if os.environ.get("REMEDIATION_EXECUTION_ENABLED", "false").lower() not in {"1", "true", "yes"}:
        raise HTTPException(status_code=503, detail="remediation_execution_disabled")
    with get_session() as session:
        remediation = session.get(Remediation, remediation_id)
        if remediation is None:
            raise HTTPException(status_code=404, detail="remediation_not_found")
        events = RemediationRepository.list_events(session, remediation_id)
        if any(event.event_type == "execution_ready" for event in events):
            raise HTTPException(status_code=409, detail="remediation_execution_already_complete")
        if any(event.event_type in {"execution_queued", "execution_started"} for event in events):
            raise HTTPException(status_code=409, detail="remediation_execution_already_queued")
        if enum_value(remediation.status) != RemediationStatus.ANALYZING.value:
            raise HTTPException(status_code=409, detail="remediation_not_approved")
        RemediationRepository.append_event(session, {
            "remediation_id": remediation_id,
            "event_type": "execution_queued",
            "sequence": len(events) + 1,
            "detail": {"action": "execution_queued"},
        })
        task = execute_approved_remediation.apply_async(args=[remediation_id], queue="remediation.normal")
        record_operator_event(session, request, AuditEventType.CONFIG_CHANGED, str(remediation_id), {"action": "remediation_execution_requested", "task_id": task.id}, entity_type="remediation")
    return {"remediation_id": remediation_id, "task_id": task.id, "status": "queued"}


@router.post("/remediations/{remediation_id}/retry")
def retry_remediation(remediation_id: int, request: Request) -> dict:
    """Return a failed execution to approval so an operator can deliberately restart it."""
    require_role(request, "security-operator")
    with get_session() as session:
        remediation = session.get(Remediation, remediation_id)
        if remediation is None:
            raise HTTPException(status_code=404, detail="remediation_not_found")
        if enum_value(remediation.status) != RemediationStatus.FAILED.value:
            raise HTTPException(status_code=409, detail="remediation_not_failed")
        RemediationRepository.update_status(session, remediation_id, RemediationStatus.REQUIRES_REVIEW)
        remediation.error_message = None
        events = RemediationRepository.list_events(session, remediation_id)
        RemediationRepository.append_event(session, {
            "remediation_id": remediation_id,
            "event_type": "execution_retry_requested",
            "sequence": len(events) + 1,
            "detail": {"action": "execution_retry_requested"},
        })
        return remediation_payload(RemediationRepository.get_by_id(session, remediation_id))
