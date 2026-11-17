"""Signed GitHub pull-request callbacks for published remediations (decision D4: GitHub only).

The callback only says what happened to the pull request. Whether the fix worked is decided by
the server's own rescan of the image (see `src/remediation/lifecycle.py`), never by anything in
the payload.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request

from src.db.connection import get_session
from src.db.models import RemediationPublication, RemediationStatus, RemediationWebhookEvent
from src.db.repositories import RemediationRepository
from src.telemetry.scan_metrics import record_provider_callback

router = APIRouter()


def verify_signature(body: bytes, signature: str, secret: str) -> bool:
    """Check GitHub's `X-Hub-Signature-256` (HMAC-SHA256 of the raw body)."""
    candidate = signature.removeprefix("sha256=")
    if not secret or not re.fullmatch(r"[a-f0-9]{64}", candidate):
        return False
    return hmac.compare_digest(candidate, hmac.new(secret.encode(), body, hashlib.sha256).hexdigest())


def queue_rescan(image_full_name: str) -> str:
    """Rescan the real image after a merge. It completes the remediation once it shows the fix."""
    from src.scan.records import queue_scan

    return queue_scan(image_full_name, priority="high", trigger="post_merge")


def _closed(session, publication: RemediationPublication, pull: dict) -> dict:
    remediation_id = publication.remediation_id
    if pull.get("merged"):
        publication.status = "merged"
        publication.merged_at = datetime.now(timezone.utc).replace(tzinfo=None)
        publication.merge_commit = str(pull.get("merge_commit_sha") or "")[:64] or None
        session.flush()
        scan_id = queue_rescan(publication.remediation.image.full_name)
        RemediationRepository.record_event(
            session,
            remediation_id,
            "merged",
            {"number": publication.provider_number, "merge_commit": publication.merge_commit, "scan_id": scan_id},
        )
        return {"publication": "merged", "scan_id": scan_id}
    publication.status = "closed"
    reason = f"pull request #{publication.provider_number} was closed without merging"
    if publication.remediation.status == RemediationStatus.PUBLISHED:
        RemediationRepository.update_status(session, remediation_id, RemediationStatus.FAILED, error_message=reason)
    RemediationRepository.record_event(session, remediation_id, "pull_request_closed", {"reason": reason})
    return {"publication": "closed"}


@router.post("/webhooks/{provider}")
async def provider_webhook(provider: str, request: Request) -> dict:
    if provider.lower() != "github":
        raise HTTPException(status_code=404, detail="provider_not_supported")
    delivery = request.headers.get("x-github-delivery", "")
    body = await request.body()
    signature = request.headers.get("x-hub-signature-256", "")
    if not delivery or not verify_signature(body, signature, os.environ.get("GITHUB_WEBHOOK_SECRET", "")):
        record_provider_callback("rejected")
        raise HTTPException(status_code=401, detail="invalid_provider_signature")
    try:
        payload = json.loads(body.decode())
        event = request.headers.get("x-github-event", "")
        action = str(payload.get("action") or "")
        pull = payload.get("pull_request") or {}
        repository = str((payload.get("repository") or {}).get("full_name") or "")
        number = int(pull.get("number") or payload.get("number") or 0)
    except (UnicodeDecodeError, ValueError, TypeError, AttributeError) as exc:
        raise HTTPException(status_code=400, detail="invalid_provider_payload") from exc

    with get_session() as session:
        if session.query(RemediationWebhookEvent).filter_by(provider="github", event_id=delivery).first():
            record_provider_callback("duplicate")
            return {"accepted": True, "duplicate": True}
        publication = (
            session.query(RemediationPublication)
            .filter_by(provider="github", repository=repository, provider_number=number)
            .first()
            if event == "pull_request" and number
            else None
        )
        session.add(
            RemediationWebhookEvent(
                remediation_id=publication.remediation_id if publication else None,
                provider="github",
                event_id=delivery[:256],
                event_type=f"{event}.{action}"[:64],
            )
        )
        if publication is None:
            record_provider_callback("unmatched")
            return {"accepted": True, "matched": False}
        result = {}
        if action == "closed" and publication.status == "open":
            result = _closed(session, publication, pull)
        record_provider_callback("accepted")
        return {"accepted": True, "matched": True, "publication_id": publication.id, **result}
