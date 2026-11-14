"""Dry-run-first backup rotation and freshness monitoring task."""

from __future__ import annotations

import json
import hashlib
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from celery import shared_task
from sqlalchemy.engine import make_url

from src.platform.backup_lifecycle import BackupArtifact, backup_fresh, rotation_plan
from src.platform.operations import BackupRotation
from src.telemetry.scan_metrics import set_backup_last_success
from src.db.connection import get_session
from src.db.models import AuditEventType, BackupExecution
from src.db.repositories import AuditLogRepository


def _pg_dump_database_url(database_url: str) -> str:
    """Convert an application SQLAlchemy URL into a pg_dump-compatible URI."""
    return make_url(database_url).set(drivername="postgresql").render_as_string(hide_password=False)


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


@shared_task(name="src.platform.backup_tasks.execute_postgres_backup", acks_late=True)
def execute_postgres_backup(execution_id: int) -> dict[str, object]:
    """Execute one explicitly approved PostgreSQL backup and record its result."""
    output_dir = Path(os.environ.get("BACKUP_OUTPUT_DIR", "/var/lib/scrutineering/backups"))
    timeout_seconds = max(30, int(os.environ.get("BACKUP_EXECUTION_TIMEOUT_SECONDS", "900")))
    with get_session() as session:
        record = session.get(BackupExecution, execution_id)
        if record is None:
            raise ValueError("backup_execution_not_found")
        if record.status not in {"queued", "failed"}:
            return {"id": execution_id, "status": record.status, "artifact_name": record.artifact_name}
        record.status = "running"
        record.error_message = None
        artifact_name = f"scrutineering-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{execution_id}.dump"
        record.artifact_name = artifact_name
        record.artifact_created_at = datetime.now(timezone.utc).replace(tzinfo=None)
        session.flush()

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / artifact_name
    database_url = os.environ.get("DATABASE_URL", "")
    if not database_url:
        error = "DATABASE_URL is required"
        with get_session() as session:
            record = session.get(BackupExecution, execution_id)
            record.status = "failed"
            record.error_message = error
        return {"id": execution_id, "status": "failed", "error": error}
    try:
        # SQLAlchemy URLs commonly include a driver suffix (for example,
        # ``postgresql+psycopg2://``), while pg_dump expects a native
        # PostgreSQL URI. Preserve credentials and connection options while
        # removing only the SQLAlchemy-specific driver name.
        pg_dump_url = _pg_dump_database_url(database_url)
        subprocess.run(
            ["pg_dump", "--format=custom", f"--file={output_path}", pg_dump_url],
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        digest = hashlib.sha256(output_path.read_bytes()).hexdigest()
        size_bytes = output_path.stat().st_size
        with get_session() as session:
            record = session.get(BackupExecution, execution_id)
            record.status = "verified"
            record.size_bytes = size_bytes
            record.verified = True
            record.sha256 = digest
            record.manifest = {"source": "postgres-pg_dump", "artifact_name": artifact_name, "sha256": digest, "size_bytes": size_bytes}
            record.error_message = None
            AuditLogRepository.record(
                session,
                event_type=AuditEventType.CONFIG_CHANGED,
                entity_type="backup_execution",
                entity_id=str(execution_id),
                detail={"action": "backup_execution_completed", "artifact_name": artifact_name, "size_bytes": size_bytes, "sha256": digest},
                actor="backup-worker",
                actor_kind="system",
            )
        set_backup_last_success(datetime.now(timezone.utc).timestamp())
        return {"id": execution_id, "status": "verified", "artifact_name": artifact_name, "size_bytes": size_bytes, "sha256": digest}
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        if output_path.exists():
            output_path.unlink()
        stderr = getattr(exc, "stderr", None)
        error = (stderr.strip() if isinstance(stderr, str) and stderr.strip() else str(exc))[:500]
        with get_session() as session:
            record = session.get(BackupExecution, execution_id)
            record.status = "failed"
            record.verified = False
            record.error_message = error
            AuditLogRepository.record(
                session,
                event_type=AuditEventType.CONFIG_CHANGED,
                entity_type="backup_execution",
                entity_id=str(execution_id),
                detail={"action": "backup_execution_failed", "error": error},
                actor="backup-worker",
                actor_kind="system",
            )
        return {"id": execution_id, "status": "failed", "error": error}


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
