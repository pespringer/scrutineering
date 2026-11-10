import pytest

from src.forensics.audit import AuditEvent, AuditLogger
from src.forensics.audit_anchor import AuditAnchor


def test_audit_anchor_requires_digest():
    assert AuditAnchor(lambda value: "anchor-1").publish("sha256:" + "a" * 64) == "anchor-1"


def test_audit_logger_anchors_verified_head_and_persists_receipt():
    logger = AuditLogger()
    logger.log(AuditEvent.SCAN_COMPLETED, "container")
    persisted = []
    receipt = logger.anchor_head(AuditAnchor(lambda value: f"external:{value[-8:]}"), persisted.append)
    assert receipt["anchor_id"].startswith("external:")
    assert receipt["head_hash"].startswith("sha256:")
    assert persisted == [receipt]
    assert logger.last_anchor == receipt


def test_audit_logger_does_not_anchor_empty_chain():
    with pytest.raises(ValueError, match="empty"):
        AuditLogger().anchor_head(AuditAnchor(lambda value: "anchor"))
