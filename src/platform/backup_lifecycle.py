"""Receiver-independent backup lifecycle contracts.

These helpers deliberately plan destructive work.  Execution remains the
responsibility of the existing explicit ``backup:postgres`` command.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.platform.operations import BackupRotation, rotate_backup_names


@dataclass(frozen=True)
class BackupArtifact:
    name: str
    created_at: datetime
    size_bytes: int
    verified: bool = False

    def validate(self) -> "BackupArtifact":
        if not self.name or Path(self.name).name != self.name:
            raise ValueError("backup name must be a filename")
        if self.created_at.tzinfo is None or self.size_bytes < 0:
            raise ValueError("backup metadata is invalid")
        return self


def backup_fresh(artifact: BackupArtifact, *, max_age_days: int = 1, now: datetime | None = None) -> bool:
    artifact.validate()
    if max_age_days < 1:
        raise ValueError("backup freshness window must be positive")
    current = now or datetime.now(timezone.utc)
    return artifact.created_at >= current - timedelta(days=max_age_days)


def rotation_plan(artifacts: list[BackupArtifact], policy: BackupRotation) -> dict[str, list[str]]:
    for artifact in artifacts:
        artifact.validate()
    keep, remove = rotate_backup_names([artifact.name for artifact in artifacts], policy)
    return {"keep": keep, "remove": remove, "dry_run": True}


def restore_preflight(*, manifest_valid: bool, target_is_isolated: bool, confirmation: bool = False) -> dict[str, object]:
    """Return a fail-closed restore plan; never performs a restore."""
    blocked = []
    if not manifest_valid:
        blocked.append("manifest_invalid")
    if not target_is_isolated:
        blocked.append("target_not_isolated")
    if not confirmation:
        blocked.append("explicit_confirmation_required")
    return {"ready": not blocked, "blocked_reasons": blocked, "dry_run": True}
