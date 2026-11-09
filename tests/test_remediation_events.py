from src.remediation.events import make_event


def test_remediation_event_has_auditable_shape():
    event = make_event(1, "verified", {"status": "passed"}, sequence=2)
    assert event["remediation_id"] == 1 and event["detail"]["status"] == "passed" and event["sequence"] == 2
