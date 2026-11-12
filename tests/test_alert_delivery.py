from src.remediation.alert_contracts import validate_alert_payload
from src.remediation.alert_delivery import delivery_key, sanitize_payload, schedule_retry
from src.db.models import RemediationAlertDelivery


def test_delivery_key_is_deterministic_and_payload_sensitive():
    first = delivery_key(4, "pager", "stale", {"count": 1})
    assert first == delivery_key(4, "pager", "stale", {"count": 1})
    assert first != delivery_key(4, "pager", "stale", {"count": 2})


def test_schedule_retry_dead_letters_at_attempt_limit():
    record = RemediationAlertDelivery(publication_id=1, delivery_key="k", receiver="pager", max_attempts=1)
    record.last_error = "receiver unavailable"
    schedule_retry(record)
    assert record.status == "dead_letter"
    assert record.next_attempt_at is None


def test_alert_payload_redacts_credential_like_fields():
    assert sanitize_payload({"token": "secret", "message": "safe"}) == {"token": "[REDACTED]", "message": "safe"}


def test_alert_contract_is_versioned_and_fail_closed():
    assert validate_alert_payload({"event_type": "stale", "publication_id": 1})["schema_version"] == "alert-v1"
    try:
        validate_alert_payload({"event_type": "stale"})
    except ValueError:
        pass
    else:
        raise AssertionError("invalid alert payload accepted")
