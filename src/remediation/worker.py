"""Fail-closed Celery boundary for approved remediation execution."""

from __future__ import annotations

import os

from celery import shared_task

from src.db.connection import get_session
from src.db.models import Remediation, RemediationStatus
from src.db.repositories import RemediationRepository


def execution_enabled() -> bool:
    return os.environ.get("REMEDIATION_EXECUTION_ENABLED", "false").lower() in {"1", "true", "yes"}


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
            return {"remediation_id": remediation_id, "status": "blocked", "reason": "remediation_not_approved"}
        repository_root = os.environ.get("REMEDIATION_REPOSITORY_ROOT", "")
        if not execution_enabled() or not repository_root:
            return {"remediation_id": remediation_id, "status": "blocked", "reason": "execution_adapter_not_configured"}
        if any(not action.file_path for action in remediation.actions):
            return {"remediation_id": remediation_id, "status": "blocked", "reason": "actions_require_explicit_file_paths"}
        return {"remediation_id": remediation_id, "status": "blocked", "reason": "execution_adapter_not_enabled"}
