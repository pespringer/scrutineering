"""Dry-run-first backup rotation and freshness monitoring task."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from celery import shared_task

from src.platform.backup_lifecycle import BackupArtifact, backup_fresh, rotation_plan
from src.platform.operations import BackupRotation
from src.telemetry.scan_metrics import set_backup_last_success
from src.db.connection import get_session
from src.db.models import AuditEventType, BackupExecution
from src.db.repositories import AuditLogRepository


def _record_artifact_observation(artifact: BackupArtifact, *, source: str) -> None:
    """Persist one idempotent artifact observation for dashboard evidence."""
    created_at = artifact.created_at.astimezone(timezone.utc).replace(tzinfo=None)
    with get_session() as session:
        existing = session.query(BackupExecution).filter_by(
            artifact_name=artifact.name, artifact_created_at=created_at,
        ).one_or_none()
        if existing is None:
            record = BackupExecution(
                artifact_name=artifact.name,
                source=source,
                status="verified" if artifact.verified else "observed",
                artifact_created_at=created_at,
                size_bytes=artifact.size_bytes,
                verified=artifact.verified,
                recorded_by="backup-scheduler",
            )
            session.add(record)
            session.flush()
            AuditLogRepository.record(
                session,
                event_type=AuditEventType.CONFIG_CHANGED,
                entity_type="backup_execution",
                entity_id=str(record.id),
                detail={"action": "backup_evidence_recorded", "artifact_name": artifact.name, "size_bytes": artifact.size_bytes, "verified": artifact.verified},
                actor="backup-scheduler",
                actor_kind="scheduler",
            )
        else:
            existing.observed_at = datetime.now(timezone.utc).replace(tzinfo=None)
            existing.size_bytes = artifact.size_bytes
            existing.verified = artifact.verified
            existing.status = "verified" if artifact.verified else "observed"


@shared_task(name="src.platform.backup_tasks.report_backup_freshness", acks_late=True)
def report_backup_freshness(*, metadata_path: str | None = None, dry_run: bool = True) -> dict:
    path = metadata_path or os.environ.get("BACKUP_METADATA_PATH", "")
    if not path:
        return {"status": "not_configured", "dry_run": dry_run, "stale": [], "rotation": None}
    with open(path, encoding="utf-8") as handle:
        records = json.load(handle)
    artifacts = [BackupArtifact(name=item["name"], created_at=datetime.fromisoformat(item["created_at"]), size_bytes=int(item["size_bytes"]), verified=bool(item.get("verified", False))) for item in records]
    keep = int(os.environ.get("BACKUP_ROTATION_KEEP", "7"))
    max_age = int(os.environ.get("BACKUP_MAX_AGE_DAYS", "30"))
    now = datetime.now().astimezone()
    if artifacts:
        set_backup_last_success(max(artifact.created_at.timestamp() for artifact in artifacts))
        for artifact in artifacts:
            _record_artifact_observation(artifact, source="backup-metadata")
    return {
        "status": "ok",
        "dry_run": dry_run,
        "stale": [artifact.name for artifact in artifacts if not backup_fresh(artifact, max_age_days=max_age, now=now)],
        "rotation": rotation_plan(artifacts, BackupRotation(keep=keep, max_age_days=max_age)),
    }
