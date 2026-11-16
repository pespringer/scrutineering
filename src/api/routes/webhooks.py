"""Signed provider callbacks (GitHub, GitLab) for published remediations."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request

from src.db.connection import get_session
from src.db.models import (
    RemediationPublication,
    RemediationWebhookEvent,
)
from src.db.repositories import RemediationRepository
from src.remediation.events import publication_event_exists
from src.remediation.post_merge import evaluate_post_merge
from src.remediation.post_merge_tasks import queue_post_merge_scan, verify_post_merge_scan
from src.remediation.provider_callbacks import normalize_callback, verify_signature
from src.remediation.rollback import build_rollback_plan
from src.telemetry.scan_metrics import record_provider_callback

router = APIRouter()


def _apply_post_merge_result(
    session, publication: RemediationPublication, result: dict, merge_commit: str | None
) -> str:
    """Persist verification and append its lifecycle event exactly once."""
    publication.verification_status = str(result["status"])
    publication.verification_detail = result
    event_type = "rollback_required" if result["status"] == "rollback_required" else "post_merge_verified"
    if result["status"] == "rollback_required":
        if merge_commit:
            try:
                publication.rollback_command = list(build_rollback_plan(merge_commit).command)
            except ValueError:
                publication.rollback_command = []
    else:
        publication.rollback_command = []
    events = RemediationRepository.list_events(session, publication.remediation_id)
    event_detail = {**result, "publication_id": publication.id}
    if not publication_event_exists(events, event_type=event_type, publication_id=publication.id, detail=result):
        RemediationRepository.append_event(
            session,
            {
                "remediation_id": publication.remediation_id,
                "event_type": event_type,
                "sequence": len(events) + 1,
                "detail": event_detail,
            },
        )
    return event_type


@router.post("/webhooks/{provider}")
async def provider_webhook(provider: str, request: Request) -> dict:
    provider = provider.lower()
    if provider not in {"github", "gitlab"}:
        raise HTTPException(status_code=404, detail="provider_not_supported")
    event_id = (
        request.headers.get("x-provider-event-id", "")
        or request.headers.get("x-github-delivery", "")
        or request.headers.get("x-gitlab-event-uuid", "")
    )
    signature = request.headers.get("x-provider-signature", "") or request.headers.get("x-hub-signature-256", "")
    secret = os.environ.get(f"{provider.upper()}_WEBHOOK_SECRET", "")
    body = await request.body()
    if not event_id or not verify_signature(provider=provider, body=body, signature=signature, secret=secret):
        record_provider_callback("rejected")
        raise HTTPException(status_code=401, detail="invalid_provider_signature")
    try:
        payload = json.loads(body.decode())
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="invalid_provider_payload") from exc
    try:
        callback = normalize_callback(
            provider=provider,
            payload=payload,
            event_id=event_id,
            event_type=request.headers.get("x-github-event") or request.headers.get("x-gitlab-event"),
        )
    except (TypeError, ValueError, KeyError) as exc:
        raise HTTPException(status_code=400, detail="invalid_provider_payload") from exc
    verification_task_id = None
    with get_session() as session:
        if session.query(RemediationWebhookEvent).filter_by(provider=provider, event_id=event_id).first():
            record_provider_callback("duplicate")
            return {"accepted": True, "duplicate": True}
        publication = (
            session.query(RemediationPublication)
            .filter_by(provider=provider, repository=callback.repository, provider_number=callback.number)
            .first()
        )
        webhook = RemediationWebhookEvent(
            remediation_id=publication.remediation_id if publication else None,
            provider=provider,
            event_id=event_id,
            event_type=callback.event_type,
        )
        session.add(webhook)
        if publication is None:
            record_provider_callback("unmatched")
            return {"accepted": True, "matched": False}
        publication.status = "merged" if callback.merged else callback.state
        publication.merged_at = (
            datetime.now(timezone.utc).replace(tzinfo=None) if callback.merged else publication.merged_at
        )
        publication.merge_commit = callback.merge_commit or publication.merge_commit
        publication.observed_digest = callback.observed_digest or publication.observed_digest
        publication.scan_status = callback.scan_status
        publication.findings_before = callback.findings_before
        publication.findings_after = callback.findings_after
        if callback.merged:
            if callback.expected_digest and callback.scan_status == "completed":
                result = evaluate_post_merge(
                    expected_digest=callback.expected_digest,
                    observed_digest=callback.observed_digest,
                    required_scan_status=callback.scan_status,
                    findings_before=callback.findings_before,
                    findings_after=callback.findings_after,
                )
                _apply_post_merge_result(session, publication, result, callback.merge_commit)
                if result["status"] == "rollback_required":
                    record_provider_callback("rollback_required")
            else:
                scan_id = queue_post_merge_scan(session, publication)
                publication.verification_status = "pending"
                publication.verification_detail = {
                    "status": "pending",
                    "reason": "deployment_evidence_not_in_provider_callback",
                    "scan_id": scan_id,
                }
                events = RemediationRepository.list_events(session, publication.remediation_id)
                if not any(
                    event.event_type == "post_merge_verification_queued"
                    and event.detail.get("publication_id") == publication.id
                    for event in events
                ):
                    RemediationRepository.append_event(
                        session,
                        {
                            "remediation_id": publication.remediation_id,
                            "event_type": "post_merge_verification_queued",
                            "sequence": len(events) + 1,
                            "detail": {
                                "publication_id": publication.id,
                                "scan_id": scan_id,
                                "reason": "deployment_evidence_not_in_provider_callback",
                            },
                        },
                    )
                verification_task_id = verify_post_merge_scan.apply_async(
                    args=[publication.id, scan_id], countdown=10
                ).id
        record_provider_callback("accepted")
        return {
            "accepted": True,
            "matched": True,
            "publication_id": publication.id,
            "verification_status": publication.verification_status,
            "verification_task_id": verification_task_id,
        }
