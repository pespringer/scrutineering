"""Dry-run-first backup rotation and freshness monitoring task."""

from __future__ import annotations

import json
import hashlib
import os
import subprocess
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from celery import shared_task
from sqlalchemy.engine import make_url

from src.platform.backup_lifecycle import BackupArtifact, backup_fresh, rotation_plan
from src.platform.operations import BackupRotation
from src.telemetry.scan_metrics import set_backup_last_success
from src.db.connection import get_session
from src.db.models import AuditEventType, BackupExecution, BackupRestoreExecution
from src.db.repositories import AuditLogRepository


def _pg_dump_database_url(database_url: str) -> str:
    """Convert an application SQLAlchemy URL into a pg_dump-compatible URI."""
    return make_url(database_url).set(drivername="postgresql").render_as_string(hide_password=False)


def _restore_table_counts(connection) -> tuple[int, dict[str, int]]:
    """Return restored user-table and known-record counts without exposing data."""
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT count(*) FROM pg_class c "
            "JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = 'public' AND c.relkind = 'r'"
        )
        table_count = int(cursor.fetchone()[0])
        row_counts: dict[str, int] = {}
        for table in ("images", "scans", "scan_findings", "audit_log"):
            cursor.execute("SELECT to_regclass(%s)", (f"public.{table}",))
            if cursor.fetchone()[0] is not None:
                cursor.execute(f'SELECT count(*) FROM public."{table}"')
                row_counts[table] = int(cursor.fetchone()[0])
    return table_count, row_counts


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


@shared_task(name="src.platform.backup_tasks.verify_postgres_restore", acks_late=True)
def verify_postgres_restore(restore_execution_id: int) -> dict[str, object]:
    """Restore a verified dump into a temporary database and prove cleanup."""
    import psycopg2
    from psycopg2 import sql

    enabled = os.environ.get("BACKUP_RESTORE_ENABLED", "false").lower() in {"1", "true", "yes"}
    isolated = os.environ.get("BACKUP_RESTORE_TARGET_ISOLATED", "false").lower() in {"1", "true", "yes"}
    admin_url = os.environ.get("BACKUP_RESTORE_ADMIN_DATABASE_URL", "")
    output_dir = Path(os.environ.get("BACKUP_OUTPUT_DIR", "/var/lib/scrutineering/backups"))
    timeout_seconds = max(30, int(os.environ.get("BACKUP_RESTORE_TIMEOUT_SECONDS", "900")))
    started = time.monotonic()
    target_name: str | None = None
    admin_connection = None
    target_connection = None
    created_target = False
    sql_dump_path: Path | None = None

    with get_session() as session:
        restore = session.get(BackupRestoreExecution, restore_execution_id)
        if restore is None:
            raise ValueError("backup_restore_execution_not_found")
        backup = session.get(BackupExecution, restore.backup_execution_id)
        if backup is None:
            raise ValueError("backup_execution_not_found")
        if restore.status not in {"queued", "failed"}:
            return {"id": restore_execution_id, "status": restore.status}
        if not backup.verified:
            restore.status = "failed"
            restore.error_message = "backup_artifact_not_verified"
            return {"id": restore_execution_id, "status": "failed", "error": restore.error_message}
        restore.status = "running"
        restore.started_at = datetime.now(timezone.utc).replace(tzinfo=None)
        restore.error_message = None
        artifact_name = backup.artifact_name

    def fail(error: str, *, cleanup_verified: bool = False) -> dict[str, object]:
        with get_session() as session:
            restore = session.get(BackupRestoreExecution, restore_execution_id)
            restore.status = "failed"
            restore.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
            restore.duration_seconds = round(time.monotonic() - started, 3)
            restore.cleanup_verified = cleanup_verified
            restore.error_message = error[:500]
            AuditLogRepository.record(
                session,
                event_type=AuditEventType.CONFIG_CHANGED,
                entity_type="backup_restore_execution",
                entity_id=str(restore_execution_id),
                detail={"action": "backup_restore_failed", "error": error[:500], "cleanup_verified": cleanup_verified},
                actor="backup-worker",
                actor_kind="system",
            )
        return {"id": restore_execution_id, "status": "failed", "error": error[:500]}

    if not enabled:
        return fail("backup_restore_disabled")
    if not isolated:
        return fail("isolated_restore_target_required")
    if not admin_url:
        return fail("BACKUP_RESTORE_ADMIN_DATABASE_URL is required")
    if Path(artifact_name).name != artifact_name:
        return fail("backup_artifact_name_must_be_a_filename")
    artifact_path = output_dir / artifact_name
    if not artifact_path.is_file():
        return fail("backup_artifact_not_found")

    try:
        admin_native_url = make_url(admin_url).set(drivername="postgresql", database="postgres").render_as_string(hide_password=False)
        admin_connection = psycopg2.connect(admin_native_url)
        admin_connection.autocommit = True
        target_name = f"scrutineering_restore_{restore_execution_id}_{uuid.uuid4().hex[:8]}"
        with admin_connection.cursor() as cursor:
            cursor.execute(sql.SQL("CREATE DATABASE {} WITH TEMPLATE template0").format(sql.Identifier(target_name)))
        created_target = True
        target_url = make_url(admin_url).set(drivername="postgresql", database=target_name).render_as_string(hide_password=False)
        sql_fd, sql_path = tempfile.mkstemp(prefix="scrutineering-restore-", suffix=".sql", dir=output_dir)
        os.close(sql_fd)
        sql_dump_path = Path(sql_path)
        subprocess.run(
            ["pg_restore", "--format=custom", "--no-owner", f"--file={sql_dump_path}", str(artifact_path)],
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        sql_dump = sql_dump_path.read_text(encoding="utf-8")
        # PostgreSQL 17's pg_dump emits this setting, which PostgreSQL 16 does
        # not recognize. The dump contents remain portable; remove only this
        # client/server session directive before executing the SQL.
        sql_dump = sql_dump.replace("SET transaction_timeout = 0;\n", "")
        subprocess.run(
            ["psql", "--set=ON_ERROR_STOP=1", f"--dbname={target_url}"],
            input=sql_dump,
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        target_connection = psycopg2.connect(target_url)
        table_count, row_counts = _restore_table_counts(target_connection)
        if table_count < 1:
            return fail("restored_database_has_no_user_tables")
        target_connection.close()
        target_connection = None
        with admin_connection.cursor() as cursor:
            cursor.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(target_name)))
        created_target = False
        with get_session() as session:
            restore = session.get(BackupRestoreExecution, restore_execution_id)
            restore.status = "verified"
            restore.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
            restore.duration_seconds = round(time.monotonic() - started, 3)
            restore.table_count = table_count
            restore.row_counts = row_counts
            restore.target_database = target_name
            restore.cleanup_verified = True
            restore.manifest = {"artifact_name": artifact_name, "table_count": table_count, "row_counts": row_counts, "target_isolated": True}
            AuditLogRepository.record(
                session,
                event_type=AuditEventType.CONFIG_CHANGED,
                entity_type="backup_restore_execution",
                entity_id=str(restore_execution_id),
                detail={"action": "backup_restore_verified", "artifact_name": artifact_name, "table_count": table_count, "row_counts": row_counts},
                actor="backup-worker",
                actor_kind="system",
            )
        return {"id": restore_execution_id, "status": "verified", "table_count": table_count, "row_counts": row_counts}
    except (OSError, psycopg2.Error, subprocess.SubprocessError, ValueError) as exc:
        stderr = getattr(exc, "stderr", None)
        error = (stderr.strip() if isinstance(stderr, str) and stderr.strip() else str(exc))
        return fail(error)
    finally:
        if sql_dump_path is not None:
            sql_dump_path.unlink(missing_ok=True)
        if target_connection is not None:
            target_connection.close()
        cleanup_verified = False
        if created_target and admin_connection is not None and target_name is not None:
            try:
                with admin_connection.cursor() as cursor:
                    cursor.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(target_name)))
                cleanup_verified = True
            except psycopg2.Error:
                cleanup_verified = False
        if admin_connection is not None:
            admin_connection.close()
        if cleanup_verified:
            with get_session() as session:
                restore = session.get(BackupRestoreExecution, restore_execution_id)
                if restore is not None:
                    restore.cleanup_verified = True


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
