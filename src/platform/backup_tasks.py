"""Dry-run-first backup rotation and freshness monitoring task."""

from __future__ import annotations

import json
import os
from datetime import datetime

from celery import shared_task

from src.platform.backup_lifecycle import BackupArtifact, backup_fresh, rotation_plan
from src.platform.operations import BackupRotation
from src.telemetry.scan_metrics import set_backup_last_success


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
    return {
        "status": "ok",
        "dry_run": dry_run,
        "stale": [artifact.name for artifact in artifacts if not backup_fresh(artifact, max_age_days=max_age, now=now)],
        "rotation": rotation_plan(artifacts, BackupRotation(keep=keep, max_age_days=max_age)),
    }
