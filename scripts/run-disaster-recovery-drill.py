"""Run a deterministic backup/restore and recovery contract drill."""

from datetime import datetime, timedelta, timezone

from src.platform.operations import BackupRotation, QuarantineRecord, RecoveryEscalation, ResourceBudget, rotate_backup_names
from src.remediation.backup import verify_restore_preflight
from src.platform.controls import backup_manifest


records = [{"id": 1, "kind": "audit"}]
manifest = backup_manifest(records, source="staging-postgres")
assert verify_restore_preflight(records, manifest)
assert rotate_backup_names(["003", "002", "001"], BackupRotation(keep=2))[1] == ["001"]
assert ResourceBudget().validate()
assert RecoveryEscalation("high", 3).needs_review()
assert QuarantineRecord("artifact-1", "restore-check", datetime.now(timezone.utc) + timedelta(minutes=1)).active()
print("PASS receiver-independent disaster-recovery drill")
