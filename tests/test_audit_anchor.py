from src.forensics.audit_anchor import AuditAnchor


def test_audit_anchor_requires_digest():
    assert AuditAnchor(lambda value: "anchor-1").publish("sha256:" + "a" * 64) == "anchor-1"
