from datetime import datetime, timedelta, timezone

import pytest

from src.platform.operations import (
    BackupRotation,
    ExportCursor,
    QuarantineRecord,
    RecoveryEscalation,
    ResourceBudget,
    filter_key,
    rotate_backup_names,
    slo_breach,
    tenant_scope,
)


def test_backup_rotation_and_export_cursor_are_bounded():
    assert rotate_backup_names(["003", "001", "002"], BackupRotation(keep=2)) == (["003", "002"], ["001"])
    assert ExportCursor(0, 10).next(25) == ExportCursor(10, 10)
    assert ExportCursor(20, 10).next(25) is None
    with pytest.raises(ValueError): BackupRotation(keep=0).validate()


def test_quarantine_resources_tenants_and_slo_contracts():
    assert QuarantineRecord("a", "validation_failed", datetime.now(timezone.utc) + timedelta(minutes=1)).active()
    assert ResourceBudget().validate().memory_mb == 1024
    assert tenant_scope("team-a", "team-a") and not tenant_scope("team-a", "team-b")
    assert RecoveryEscalation("critical", 0).needs_review()
    assert slo_breach(301, 0) and not slo_breach(1, 0)
    assert len(filter_key({"actor": "ops"})) == 16
