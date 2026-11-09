from src.forensics.audit import AuditLogger, verify_audit_chain


def test_audit_chain_detects_tampering():
    logger = AuditLogger()
    logger.log("first", "c1")
    logger.log("second", "c1")
    records = logger.query()
    assert verify_audit_chain(records)
    records[0]["detail"] = {"tampered": True}
    assert not verify_audit_chain(records)
