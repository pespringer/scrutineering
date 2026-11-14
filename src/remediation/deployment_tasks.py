"""Queued deployment observation and publication reconciliation."""

from __future__ import annotations

from datetime import datetime, timezone
import os

from celery import shared_task

from src.db.connection import get_session
from src.db.models import RemediationPublication, RemediationReleaseEvidence, Scan, ScanStatus
from src.db.repositories import RemediationRepository
from src.remediation.deployment_collectors import DeploymentCollectorError, collect_observation, observation_payload
from src.remediation.deployment_config import configured_deployment_target
from src.remediation.post_merge import evaluate_post_merge
from src.remediation.rollback import build_rollback_plan


def _append_event(session, publication, event_type: str, detail: dict) -> None:
    events = RemediationRepository.list_events(session, publication.remediation_id)
    if any(event.event_type == event_type and event.detail.get("publication_id") == publication.id for event in events):
        return
    RemediationRepository.append_event(session, {
        "remediation_id": publication.remediation_id,
        "event_type": event_type,
        "sequence": len(events) + 1,
        "detail": {"publication_id": publication.id, **detail},
    })


def _reconcile_observation(session, publication, observation: dict, scan: Scan | None) -> dict:
    """Persist an observation and decide only when all required facts exist."""
    publication.observed_digest = observation["observed_digest"]
    detail = {"status": "pending", "observation": observation}
    if scan is None or scan.status in {ScanStatus.PENDING, ScanStatus.RUNNING}:
        detail["reason"] = "post_merge_scan_pending"
        publication.verification_status = "pending"
        publication.verification_detail = detail
        return detail
    scan_status = scan.status.value if hasattr(scan.status, "value") else str(scan.status)
    publication.scan_status = scan_status
    findings_before = publication.findings_before if publication.findings_before is not None else publication.remediation.finding_count
    findings_after = scan.total_findings or 0
    publication.findings_before = findings_before
    publication.findings_after = findings_after
    image_digest = publication.remediation.image.digest if publication.remediation.image else None
    if not image_digest:
        detail["reason"] = "expected_artifact_digest_required"
        detail.update({"findings_before": findings_before, "findings_after": findings_after})
        publication.verification_status = "pending"
        publication.verification_detail = detail
        return detail
    result = evaluate_post_merge(
        expected_digest=image_digest, observed_digest=publication.observed_digest,
        required_scan_status=scan_status, findings_before=findings_before,
        findings_after=findings_after,
    )
    detail.update(result)
    detail.update({"expected_digest": image_digest, "findings_before": findings_before, "findings_after": findings_after})
    publication.verification_status = str(result["status"])
    publication.verification_detail = detail
    if result["status"] == "rollback_required" and publication.merge_commit:
        publication.rollback_command = list(build_rollback_plan(publication.merge_commit).command)
    event_type = "post_merge_verified" if result["status"] == "verified" else "rollback_required"
    _append_event(session, publication, event_type, detail)
    if not session.query(RemediationReleaseEvidence).filter_by(publication_id=publication.id, evidence_key=observation["evidence_fingerprint"]).first():
        session.add(RemediationReleaseEvidence(
            publication_id=publication.id, evidence_key=observation["evidence_fingerprint"],
            expected_digest=image_digest, observed_digest=publication.observed_digest,
            scan_status=scan_status, findings_before=findings_before,
            findings_after=findings_after, status=str(result["status"]),
            verification_detail=detail,
            verified_at=datetime.now(timezone.utc).replace(tzinfo=None)
            if result["status"] == "verified" else None,
        ))
    return detail


@shared_task(name="src.remediation.deployment_tasks.collect_deployment_observation", acks_late=True)
def collect_deployment_observation(publication_id: int) -> dict:
    """Collect and reconcile one configured runtime observation."""
    with get_session() as session:
        publication = session.get(RemediationPublication, publication_id)
        if publication is None:
            return {"publication_id": publication_id, "status": "not_found"}
        if publication.status != "merged":
            raise DeploymentCollectorError("deployment observation requires a merged publication")
        target = configured_deployment_target(publication.repository)
        timeout = int(os.environ.get("DEPLOYMENT_COLLECTOR_TIMEOUT_SECONDS", "20"))
        observation = collect_observation(target, timeout_seconds=timeout)
        scan = session.query(Scan).filter_by(scan_id=publication.post_merge_scan_id).first() if publication.post_merge_scan_id else None
        detail = _reconcile_observation(session, publication, observation_payload(observation), scan)
        return {"publication_id": publication_id, "status": detail["status"], "verification_status": publication.verification_status, "observation": observation_payload(observation)}
