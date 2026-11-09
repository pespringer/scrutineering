from src.remediation.events import make_event


def test_remediation_event_has_auditable_shape():
    event = make_event(1, "verified", {"status": "passed"})
    assert event["remediation_id"] == 1 and event["detail"]["status"] == "passed"
