"""Fail-closed Celery boundary for approved remediation execution."""

from __future__ import annotations

import os
import json
import subprocess
import hashlib
from datetime import datetime, timezone

from celery import shared_task

from src.db.connection import get_session
from src.db.models import Remediation, RemediationPublication, RemediationStatus
from src.db.repositories import RemediationRepository
from .adapter import build_validation_sequence, execute_repository_adapter, load_release_evidence
from .publisher import publish_remediation_branch
from .publication import build_publication_plan
from .provider_publishers import publish_validated_plan


def execution_enabled() -> bool:
    return os.environ.get("REMEDIATION_EXECUTION_ENABLED", "false").lower() in {"1", "true", "yes"}


def _blocked(session, remediation_id: int, reason: str) -> dict:
    remediation = RemediationRepository.get_by_id(session, remediation_id)
    if remediation is not None:
        terminal = {
            RemediationStatus.COMPLETED,
            RemediationStatus.FAILED,
            RemediationStatus.SKIPPED,
        }
        if remediation.status not in terminal:
            RemediationRepository.update_status(
                session, remediation_id, RemediationStatus.FAILED,
                error_message=reason,
            )
        else:
            remediation.error_message = reason
    events = RemediationRepository.list_events(session, remediation_id)
    RemediationRepository.append_event(session, {
        "remediation_id": remediation_id,
        "event_type": "execution_blocked",
        "sequence": len(events) + 1,
        "detail": {"reason": reason},
    })
    return {"remediation_id": remediation_id, "status": "blocked", "reason": reason}


def _publish_branch(session, remediation, branch_name: str, commit: str) -> dict:
    """Publish one validated branch through the existing provider gates."""
    provider = os.environ.get("REMEDIATION_PUBLICATION_PROVIDER", "github").strip().lower()
    repository = os.environ.get("REMEDIATION_PUBLICATION_REPOSITORY", "").strip()
    base = os.environ.get("REMEDIATION_PUBLICATION_BASE", "main").strip()
    allowed = {value.strip() for value in os.environ.get("REMEDIATION_ALLOWED_REPOSITORIES", "").split(",") if value.strip()}
    idempotency_key = f"remediation-{remediation.id}-{commit}"
    plan = build_publication_plan(
        provider=provider, repository=repository, head=branch_name, base=base,
        idempotency_key=idempotency_key, commit=commit, evidence_verified=True,
        allowed_repositories=allowed,
    )
    title = f"Apply verified security remediation #{remediation.id}"
    body = ("This pull request was created by Scrutineering after approval, "
            "signed evidence verification, isolated validation, and a clean "
            f"remediation commit ({commit}).\n\nRemediation: {remediation.id}")
    request_hash = hashlib.sha256(json.dumps({"provider": plan.provider, "repository": plan.repository, "head": plan.head, "base": plan.base, "commit": commit}, sort_keys=True).encode()).hexdigest()
    publication = session.query(RemediationPublication).filter_by(
        provider=plan.provider, repository=plan.repository,
        idempotency_key=plan.idempotency_key,
    ).first()
    if publication and publication.status == "published":
        return {"publication_id": publication.id, "status": publication.status, "number": publication.provider_number, "url": publication.url}
    publication = publication or RemediationPublication(
        remediation_id=remediation.id, provider=plan.provider,
        repository=plan.repository, idempotency_key=plan.idempotency_key,
        status="pending", request_hash=request_hash,
    )
    session.add(publication)
    session.flush()
    token = os.environ.get("GITHUB_TOKEN" if plan.provider == "github" else "GITLAB_TOKEN", "")
    try:
        result = publish_validated_plan(
            provider=plan.provider, repository=plan.repository, title=title,
            body=body, head=plan.head, base=plan.base, token=token,
            idempotency_key=plan.idempotency_key,
        )
    except Exception as exc:
        publication.status = "failed"
        publication.error_message = str(exc)[:1000]
        publication.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
        raise
    publication.status = "published"
    publication.provider_number = result.number
    publication.url = result.url
    publication.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
    remediation.pr_url = result.url
    remediation.pr_number = result.number
    remediation.status = RemediationStatus.PR_OPENED
    return {"publication_id": publication.id, "status": publication.status, "number": result.number, "url": result.url}


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
                validation_working_directory=os.environ.get("REMEDIATION_VALIDATION_WORKING_DIRECTORY") or None,
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
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
                return _blocked(session, remediation_id, f"branch_publication_failed:{exc}")
            remediation.branch_name = published["branch_name"]
        publication = None
        if os.environ.get("REMEDIATION_PUBLICATION_ENABLED", "false").lower() in {"1", "true", "yes"}:
            if not branch_name:
                return _blocked(session, remediation_id, "publication_requires_branch_push")
            try:
                publication = _publish_branch(session, remediation, branch_name, result.commit or "")
            except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
                return _blocked(session, remediation_id, f"provider_publication_failed:{exc}")
        events = RemediationRepository.list_events(session, remediation_id)
        detail = {"commit": result.commit, "branch_name": branch_name, "changed_files": result.changed_files}
        if publication:
            detail["publication"] = publication
        if remediation.status == RemediationStatus.ANALYZING:
            RemediationRepository.update_status(session, remediation_id, RemediationStatus.COMPLETED)
        RemediationRepository.append_event(session, {"remediation_id": remediation_id, "event_type": "execution_ready", "sequence": len(events) + 1, "detail": detail})
        return {"remediation_id": remediation_id, "status": "ready", "commit": result.commit, "branch_name": branch_name, "publication": publication, "changed_files": result.changed_files}
