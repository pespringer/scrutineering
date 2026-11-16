import pytest
import hashlib
import hmac

from src.remediation.provider_callbacks import normalize_callback, verify_signature
from src.remediation.events import publication_event_exists, recovery_request_exists


def test_github_callback_normalizes_native_merge_payload():
    callback = normalize_callback(
        provider="github",
        event_id="delivery-1",
        event_type="pull_request",
        payload={
            "action": "closed",
            "repository": {"full_name": "org/app"},
            "number": 12,
            "pull_request": {"merged": True, "merge_commit_sha": "a" * 40, "state": "closed"},
            "expected_digest": "sha256:" + "a" * 64,
            "observed_digest": "sha256:" + "a" * 64,
            "scan_status": "completed",
            "findings_before": 4,
            "findings_after": 2,
        },
    )
    assert callback.repository == "org/app"
    assert callback.number == 12
    assert callback.merged is True
    assert callback.findings_after == 2


def test_github_is_the_only_provider():
    with pytest.raises(ValueError):
        normalize_callback(provider="gitlab", event_id="event-1", payload={})


def test_provider_signature_accepts_github_prefix_and_rejects_wrong_secret():
    body = b'{"action":"closed"}'
    digest = hmac.new(b"secret", body, hashlib.sha256).hexdigest()
    assert verify_signature(provider="github", body=body, signature=f"sha256={digest}", secret="secret")
    assert not verify_signature(provider="github", body=body, signature=digest, secret="wrong")


def test_post_merge_event_is_idempotent_per_publication():
    result = {"status": "verified", "reasons": [], "findings_delta": -1}
    event = type("Event", (), {"event_type": "post_merge_verified", "detail": {**result, "publication_id": 2}})()
    assert publication_event_exists([event], event_type="post_merge_verified", publication_id=2, detail=result)
    assert not publication_event_exists([event], event_type="post_merge_verified", publication_id=3, detail=result)


def test_recovery_request_uses_operator_idempotency_key():
    event = type(
        "Event",
        (),
        {
            "event_type": "publication_recovery_requested",
            "detail": {"publication_id": 2, "idempotency_key": "retry-1", "action": "request_callback"},
        },
    )()
    assert recovery_request_exists([event], publication_id=2, idempotency_key="retry-1")["action"] == "request_callback"
    assert recovery_request_exists([event], publication_id=2, idempotency_key="retry-2") is None


def test_only_the_github_webhook_route_exists(monkeypatch):
    from fastapi.testclient import TestClient

    from src.api.app import create_app

    monkeypatch.setenv("PYTHON_API_KEY", "webhook-key")
    client = TestClient(create_app())
    response = client.post("/api/dashboard/webhooks/gitlab", content=b"{}", headers={"x-api-key": "webhook-key"})
    assert response.status_code == 404
    unsigned = client.post("/api/dashboard/webhooks/github", content=b"{}", headers={"x-github-delivery": "1"})
    assert unsigned.status_code == 401
