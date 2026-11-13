"""Fail-closed Celery boundary for approved remediation execution."""

from __future__ import annotations

import os
import json
import subprocess

from celery import shared_task

from src.db.connection import get_session
from src.db.models import Remediation, RemediationStatus
from src.db.repositories import RemediationRepository
from .adapter import build_validation_sequence, execute_repository_adapter, load_release_evidence
from .publisher import publish_remediation_branch


def execution_enabled() -> bool:
    return os.environ.get("REMEDIATION_EXECUTION_ENABLED", "false").lower() in {"1", "true", "yes"}


def _blocked(session, remediation_id: int, reason: str) -> dict:
    events = RemediationRepository.list_events(session, remediation_id)
    RemediationRepository.append_event(session, {
        "remediation_id": remediation_id,
        "event_type": "execution_blocked",
        "sequence": len(events) + 1,
        "detail": {"reason": reason},
    })
    return {"remediation_id": remediation_id, "status": "blocked", "reason": reason}


@shared_task(bind=True, name="src.remediation.worker.execute_approved_remediation", acks_late=True, task_time_limit=3600)
def execute_approved_remediation(self, remediation_id: int) -> dict:
    """Validate an approved record before handing it to a configured adapter.

    The adapter is intentionally not implicit: without an explicit repository
    root and execution enablement this task performs no mutation and reports a
    durable blocked result.
    """
    with get_session() as session:
        remediation = RemediationRepository.get_by_id(session, remediation_id)
        if remediation is None:
            return {"remediation_id": remediation_id, "status": "blocked", "reason": "remediation_not_found"}
        if remediation.status != RemediationStatus.ANALYZING:
            return _blocked(session, remediation_id, "remediation_not_approved")
        repository_root = os.environ.get("REMEDIATION_REPOSITORY_ROOT", "")
        if not execution_enabled() or not repository_root:
            return _blocked(session, remediation_id, "execution_adapter_not_configured")
        if any(not action.file_path for action in remediation.actions):
            return _blocked(session, remediation_id, "actions_require_explicit_file_paths")
        envelope_path = os.environ.get("REMEDIATION_EVIDENCE_FILE", "")
        artifact_path = os.environ.get("REMEDIATION_EVIDENCE_ARTIFACT_FILE", "")
        provider = os.environ.get("REMEDIATION_VALIDATION_PROVIDER", "")
        ecosystem = os.environ.get("REMEDIATION_VALIDATION_ECOSYSTEM", "")
        if not envelope_path or not artifact_path or not provider or not ecosystem:
            return _blocked(session, remediation_id, "evidence_or_validation_config_missing")
        try:
            envelope, artifact = load_release_evidence(envelope_path, artifact_path)
            validation_commands = build_validation_sequence(provider, ecosystem)
            result = execute_repository_adapter(
                repository_root,
                [{"file_path": action.file_path, "before_value": action.before_value, "after_value": action.after_value} for action in remediation.actions],
                validation_commands,
                evidence_envelope=envelope,
                evidence_artifact=artifact,
                evidence_env=dict(os.environ),
                remediation_id=str(remediation_id),
            )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return _blocked(session, remediation_id, f"execution_plan_invalid:{exc}")
        if result.status != "ready":
            return _blocked(session, remediation_id, result.error or "execution_failed")
        branch_name = None
        if os.environ.get("REMEDIATION_PUSH_ENABLED", "false").lower() in {"1", "true", "yes"}:
            if not result.commit:
                return _blocked(session, remediation_id, "validated_changes_did_not_produce_commit")
            branch_name = f"{os.environ.get('REMEDIATION_BRANCH_PREFIX', 'scrutineering/remediation').strip('/')}/{remediation_id}"
            try:
                published = publish_remediation_branch(
                    repository_root, result.commit, branch_name,
                    token=os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"),
                    remote=os.environ.get("REMEDIATION_GIT_REMOTE", "origin"),
                )
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                return _blocked(session, remediation_id, f"branch_publication_failed:{exc}")
            remediation.branch_name = published["branch_name"]
        events = RemediationRepository.list_events(session, remediation_id)
        RemediationRepository.append_event(session, {"remediation_id": remediation_id, "event_type": "execution_ready", "sequence": len(events) + 1, "detail": {"commit": result.commit, "branch_name": branch_name, "changed_files": result.changed_files}})
        return {"remediation_id": remediation_id, "status": "ready", "commit": result.commit, "branch_name": branch_name, "changed_files": result.changed_files}
