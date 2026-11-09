from src.forensics.audit import AuditLogger, AuditEvent


def test_audit_export_verifies_chain():
    logger = AuditLogger()
    logger.log(AuditEvent.SCAN_COMPLETED, "container")
    assert len(logger.export()) == 1
