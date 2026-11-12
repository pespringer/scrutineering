from src.remediation.evidence_export import sign_export, verify_export


def test_signed_evidence_export_round_trips():
    payload = {"publication_id": 1, "status": "verified"}
    envelope = sign_export(payload, "secret")
    assert verify_export(payload, envelope, "secret")
    assert not verify_export({"publication_id": 2}, envelope, "secret")
