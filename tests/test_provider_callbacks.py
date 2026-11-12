import hashlib
import hmac

from src.remediation.provider_callbacks import normalize_callback, verify_signature
from src.remediation.events import publication_event_exists


def test_github_callback_normalizes_native_merge_payload():
    callback = normalize_callback(
        provider="github", event_id="delivery-1", event_type="pull_request",
        payload={"action": "closed", "repository": {"full_name": "org/app"}, "number": 12,
                 "pull_request": {"merged": True, "merge_commit_sha": "a" * 40, "state": "closed"},
                 "expected_digest": "sha256:" + "a" * 64, "observed_digest": "sha256:" + "a" * 64,
                 "scan_status": "completed", "findings_before": 4, "findings_after": 2},
    )
    assert callback.repository == "org/app"
    assert callback.number == 12
    assert callback.merged is True
    assert callback.findings_after == 2


def test_gitlab_callback_normalizes_merge_request_payload():
    callback = normalize_callback(
        provider="gitlab", event_id="event-1",
        payload={"event_name": "merge_request", "project": {"path_with_namespace": "org/app"},
                 "object_attributes": {"iid": 7, "state": "merged", "merge_commit_sha": "b" * 40}},
    )
    assert callback.repository == "org/app"
    assert callback.number == 7
    assert callback.merged is True


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
