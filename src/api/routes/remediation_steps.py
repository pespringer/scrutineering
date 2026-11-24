"""The steps a remediation goes through after it is proposed: approve, execute, accept, publish, retry, cancel."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request

from src.config import get_settings
from src.db.connection import get_session
from src.db.models import AuditEventType, Remediation, RemediationStatus, ScanFinding
from src.db.repositories import RemediationRepository
from src.remediation.state_machine import TRANSITIONS
from src.remediation.publish import publish_remediation, token as github_token
from src.remediation.sources import publication_target, snapshot
from src.remediation.worker import execute_approved_remediation
from src.api.serializers import enum_value, remediation_payload
from src.api.routes._access import record_operator_event
from src.api.roles import require_action, require_separate_approver

router = APIRouter()


def _load(session, remediation_id: int) -> Remediation:
    remediation = session.get(Remediation, remediation_id)
    if remediation is None:
        raise HTTPException(status_code=404, detail="remediation_not_found")
    return remediation


def _require_status(remediation: Remediation, *allowed: RemediationStatus) -> Remediation:
    if remediation.status not in allowed:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "invalid_remediation_status",
                "status": enum_value(remediation.status),
                "allowed": [status.value for status in allowed],
            },
        )
    return remediation


def request_actor(request: Request) -> str:
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
    require_action(request, "remediations.approve")
    approver = request_actor(request)
    with get_session() as session:
        remediation = _require_status(_load(session, remediation_id), RemediationStatus.PROPOSED)
        require_separate_approver(request, remediation)
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
    require_action(request, "remediations.execute")
    if not get_settings().remediation_execution_enabled:
        raise HTTPException(status_code=503, detail="remediation_execution_disabled")
    with get_session() as session:
        _require_status(_load(session, remediation_id), RemediationStatus.APPROVED)
        RemediationRepository.update_status(
            session, remediation_id, RemediationStatus.BUILDING, error_message=None, executed_by=request_actor(request)
        )
        RemediationRepository.record_event(session, remediation_id, "execution_queued", {"by": request_actor(request)})
    # Dispatch after the status commit so the worker always sees `building`.
    task = execute_approved_remediation.apply_async(args=[remediation_id], queue="remediation.normal")
    with get_session() as session:
        _audit(session, request, remediation_id, "remediation_execution_requested", task_id=task.id)
    return {"remediation_id": remediation_id, "task_id": task.id, "status": RemediationStatus.BUILDING.value}


@router.post("/remediations/{remediation_id}/accept")
def accept_remediation(remediation_id: int, request: Request) -> dict:
    """Accept a verified candidate that introduced new critical/high findings (decision D6)."""
    require_action(request, "remediations.accept")
    with get_session() as session:
        remediation = _require_status(_load(session, remediation_id), RemediationStatus.NEEDS_ACCEPTANCE)
        require_separate_approver(request, remediation)
        RemediationRepository.update_status(
            session, remediation_id, RemediationStatus.READY, accepted_by=request_actor(request)
        )
        RemediationRepository.record_event(session, remediation_id, "accepted", {"by": request_actor(request)})
        _audit(session, request, remediation_id, "remediation_new_findings_accepted")
        return remediation_payload(RemediationRepository.get_by_id(session, remediation_id))


@router.post("/remediations/{remediation_id}/publish", status_code=202)
def publish_remediation_route(remediation_id: int, request: Request) -> dict:
    """Open a pull request with the verified patch on the source's provider. Only ever on an operator's request."""
    require_action(request, "remediations.publish")
    if not github_token():
        raise HTTPException(status_code=503, detail="publication_not_configured")
    with get_session() as session:
        remediation = _load(session, remediation_id)
        _require_status(remediation, RemediationStatus.READY)
        if publication_target((remediation.source or {}).get("repository")) is None:
            raise HTTPException(status_code=422, detail="source_not_on_github")
        remediation.published_by = request_actor(request)
        RemediationRepository.record_event(
            session, remediation_id, "publication_queued", {"by": request_actor(request)}
        )
    task = publish_remediation.apply_async(args=[remediation_id], queue="remediation.normal")
    with get_session() as session:
        _audit(session, request, remediation_id, "remediation_publication_requested", task_id=task.id)
    return {"remediation_id": remediation_id, "task_id": task.id, "status": RemediationStatus.READY.value}


@router.post("/remediations/{remediation_id}/retry")
def retry_remediation(remediation_id: int, request: Request) -> dict:
    """Return a failed remediation to approval so an operator can deliberately restart it."""
    require_action(request, "remediations.retry")
    with get_session() as session:
        failed = _load(session, remediation_id)
        _require_status(failed, RemediationStatus.FAILED)
        if failed.image.source is None:
            raise HTTPException(
                status_code=409,
                detail={"code": "source_not_connected", "reason": "Connect the image's source repository first."},
            )
        RemediationRepository.update_status(session, remediation_id, RemediationStatus.PROPOSED)
        remediation = session.get(Remediation, remediation_id)
        remediation.error_message = None
        # A retry is approved afresh, so it takes the source as it is now.
        remediation.source = snapshot(remediation.image.source)
        remediation.approved_by = None
        remediation.approved_at = None
        # A retry is a new proposal by whoever asked for it, so it needs a fresh approval from someone else.
        remediation.proposed_by = request_actor(request)
        remediation.executed_by = remediation.accepted_by = remediation.published_by = None
        RemediationRepository.record_event(session, remediation_id, "retry_requested", {"by": request_actor(request)})
        _audit(session, request, remediation_id, "remediation_retry_requested")
        return remediation_payload(RemediationRepository.get_by_id(session, remediation_id))


@router.post("/remediations/{remediation_id}/cancel")
def cancel_remediation(remediation_id: int, request: Request) -> dict:
    """Stop a remediation and release its findings so they can be proposed again."""
    require_action(request, "remediations.cancel")
    with get_session() as session:
        remediation = _load(session, remediation_id)
        _require_status(
            remediation, *(status for status in RemediationStatus if RemediationStatus.CANCELLED in TRANSITIONS[status])
        )
        RemediationRepository.update_status(session, remediation_id, RemediationStatus.CANCELLED)
        for finding in session.query(ScanFinding).filter(ScanFinding.remediation_id == remediation_id):
            finding.remediation_id = None
        RemediationRepository.record_event(session, remediation_id, "cancelled", {"by": request_actor(request)})
        _audit(session, request, remediation_id, "remediation_cancelled")
        return remediation_payload(RemediationRepository.get_by_id(session, remediation_id))
