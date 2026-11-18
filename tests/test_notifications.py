"""Notifications: written to the outbox with the status change, delivered by the worker, signed."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import httpx
import pytest

from src.config import REMEDIATION_STATUSES, get_settings
from src.db.connection import get_session
from src.db.models import (
    Image,
    Notification,
    RemediationActionType,
    RemediationPublication,
    RemediationStatus,
)
from src.db.repositories import RemediationRepository
from src.notifications import delivery, outbox, slack, webhook
from tests.test_remediation_planning_api import _connect, client, image  # noqa: F401  # fixtures

URL = "https://hooks.example.test/scrutineering"
SECRET = "notify-secret"
S = RemediationStatus


@pytest.fixture
def configured(monkeypatch):
    """A webhook channel, with queued deliveries counted instead of sent to a broker."""
    monkeypatch.setenv("NOTIFICATION_WEBHOOK_URL", URL)
    monkeypatch.setenv("NOTIFICATION_WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("DASHBOARD_PUBLIC_URL", "https://scrutineering.home.lan/")
    queued = []
    monkeypatch.setattr(outbox, "enqueue_delivery", lambda: queued.append(1))
    return queued


@pytest.fixture
def receiver(monkeypatch):
    """An in-process receiver; set `status` to make it refuse."""
    state = {"requests": [], "status": 200}

    def handle(request: httpx.Request) -> httpx.Response:
        state["requests"].append(request)
        return httpx.Response(state["status"])

    monkeypatch.setattr(delivery, "transport", httpx.MockTransport(handle))
    return state


def _remediation(status: S = S.PROPOSED) -> int:
    with get_session() as session:
        image = Image(repo_name="registry:5000/team/app", tag="1.0")
        session.add(image)
        session.flush()
        remediation = RemediationRepository.create(session, image_id=image.id, finding_count=2)
        RemediationRepository.add_action(session, remediation.id, RemediationActionType.DEPENDENCY_UPDATE)
        remediation.status = status
        return remediation.id


def _rows() -> list[Notification]:
    with get_session() as session:
        return session.query(Notification).order_by(Notification.id).all()


def _advance(remediation_id: int, *statuses: S, **values) -> None:
    for status in statuses:
        with get_session() as session:
            RemediationRepository.update_status(session, remediation_id, status, **values)


def test_nothing_is_written_when_no_channel_is_configured():
    rid = _remediation()
    _advance(rid, S.APPROVED, S.BUILDING, S.FAILED)
    assert _rows() == []


def test_a_status_change_in_the_events_writes_one_row_per_channel_and_queues_delivery(configured):
    rid = _remediation(S.VERIFYING)
    _advance(rid, S.NEEDS_ACCEPTANCE)

    [row] = _rows()
    assert (row.channel, row.event, row.status, row.attempts) == (
        "webhook",
        "remediation.needs_acceptance",
        "pending",
        0,
    )
    assert row.remediation_id == rid
    assert configured == [1]


def test_statuses_outside_the_events_send_nothing(configured, monkeypatch):
    rid = _remediation()
    _advance(rid, S.APPROVED, S.BUILDING, S.VERIFYING)  # not in the default events
    monkeypatch.setenv("NOTIFICATION_EVENTS", "completed")
    _advance(rid, S.READY)
    assert _rows() == [] and configured == []


def test_a_rolled_back_status_change_sends_nothing(configured):
    rid = _remediation(S.VERIFYING)
    with pytest.raises(RuntimeError):
        with get_session() as session:
            RemediationRepository.update_status(session, rid, S.READY)
            raise RuntimeError("the transaction fails after the status change")
    assert _rows() == [] and configured == []


def test_the_payload_describes_the_remediation_at_the_change(configured):
    rid = _remediation(S.READY)
    with get_session() as session:
        session.add(
            RemediationPublication(
                remediation_id=rid,
                provider="github",
                repository="team/app",
                idempotency_key="k",
                status="open",
                url="https://github.com/team/app/pull/7",
                request_hash="h",
            )
        )
    _advance(rid, S.PUBLISHED)
    _advance(rid, S.FAILED, error_message="the pull request was closed without merging\n" + "build output " * 100)

    published, failed = (row.payload for row in _rows())
    assert published["event"] == "remediation.published"
    assert published["remediation"] == {
        "id": rid,
        "status": "published",
        "label": "Pull request open",
        "image": "registry:5000/team/app:1.0",
        "action": "dependency_update",
        "targets": 2,
        "new_critical_high": [],
        "pull_request_url": "https://github.com/team/app/pull/7",
        "error": None,
        "url": f"https://scrutineering.home.lan/remediations/{rid}",
    }
    assert failed["remediation"]["status"] == "failed"
    assert failed["remediation"]["error"] == "the pull request was closed without merging"


def test_new_critical_findings_are_listed_and_errors_are_cut(configured):
    rid = _remediation(S.VERIFYING)
    blocking = [{"cve_id": "CVE-2026-2", "package_name": "b"}, {"cve_id": "CVE-2026-1", "package_name": "a"}]
    _advance(rid, S.NEEDS_ACCEPTANCE, verification={"new_critical_or_high": blocking})
    assert _rows()[0].payload["remediation"]["new_critical_high"] == ["CVE-2026-1", "CVE-2026-2"]
    assert len(outbox._first_line("x" * 1000)) == outbox.MAX_ERROR


def test_creating_a_remediation_through_the_api_notifies_proposed(configured, client, image):  # noqa: F811
    """Creation sets `proposed` without update_status; the route records it once the actions exist."""
    image_id, ids = image
    _connect(client, image_id)
    body = {"image_id": image_id, "finding_ids": [ids["lodash-trivy"]]}
    response = client.post("/api/dashboard/remediations", json=body)
    assert response.status_code == 201, response.text
    [row] = _rows()
    assert row.event == "remediation.proposed"
    assert row.payload["remediation"]["action"] == "dependency_update"


def test_a_delivered_webhook_is_signed_and_marked_sent(configured, receiver):
    rid = _remediation(S.VERIFYING)
    _advance(rid, S.READY)

    assert delivery.deliver() == {"sent": 1, "retrying": 0, "failed": 0, "deleted": 0}
    [request] = receiver["requests"]
    assert str(request.url) == URL
    body = request.content
    assert request.headers[webhook.SIGNATURE_HEADER] == webhook.signature(SECRET, body)
    assert request.headers[webhook.EVENT_HEADER] == "remediation.ready"
    [row] = _rows()
    assert request.headers[webhook.DELIVERY_HEADER] == str(row.id)
    assert json.loads(body)["id"] == row.id
    assert (row.status, row.attempts, row.last_error) == ("sent", 1, None)
    assert row.sent_at is not None


def test_the_signature_matches_a_known_vector():
    raw = webhook.body(1, {"event": "test"})
    assert raw == b'{"event":"test","id":1}'
    assert webhook.signature("shh", raw) == "sha256=1205e7c19bf91874077d2eb95aea36e47608993bff3bee00bf8cbc3102d16dc0"


def _make_due() -> None:
    with get_session() as session:
        for row in session.query(Notification):
            row.next_attempt_at = outbox.now() - timedelta(seconds=1)


def test_refused_deliveries_retry_with_backoff_then_fail(configured, receiver):
    receiver["status"] = 503
    rid = _remediation(S.VERIFYING)
    _advance(rid, S.READY)

    assert delivery.deliver()["retrying"] == 1
    [row] = _rows()
    assert row.status == "pending" and row.last_error == "HTTP 503"
    assert row.next_attempt_at - outbox.now() > timedelta(seconds=50)
    assert delivery.deliver()["retrying"] == 0  # not due yet
    for _ in range(delivery.MAX_ATTEMPTS - 1):
        _make_due()
        delivery.deliver()
    [row] = _rows()
    assert (row.status, row.attempts) == ("failed", delivery.MAX_ATTEMPTS)
    assert len(receiver["requests"]) == delivery.MAX_ATTEMPTS


def test_errors_never_contain_the_url_and_redirects_are_not_followed(configured, monkeypatch):
    def unreachable(request):
        raise httpx.ConnectError(f"cannot connect to {request.url}")

    monkeypatch.setattr(delivery, "transport", httpx.MockTransport(unreachable))
    _advance(_remediation(S.VERIFYING), S.READY)
    delivery.deliver()
    assert _rows()[0].last_error == "ConnectError: could not reach the receiver"

    monkeypatch.setattr(
        delivery, "transport", httpx.MockTransport(lambda request: httpx.Response(302, headers={"location": URL}))
    )
    _make_due()
    delivery.deliver()
    assert _rows()[0].last_error == "HTTP 302"


def test_old_sent_rows_are_deleted_and_failed_rows_are_kept(configured, receiver):
    rid = _remediation(S.VERIFYING)
    _advance(rid, S.READY, S.PUBLISHED)
    delivery.deliver()
    with get_session() as session:
        first, second = session.query(Notification).order_by(Notification.id).all()
        first.sent_at = outbox.now() - timedelta(days=31)
        second.status, second.sent_at = "failed", None
    assert delivery.deliver()["deleted"] == 1
    assert [row.status for row in _rows()] == ["failed"]


def test_a_sample_message_uses_the_same_outbox(configured, receiver):
    with get_session() as session:
        [row] = outbox.sample_message(session)
    assert configured == [1]
    delivery.deliver()
    assert json.loads(receiver["requests"][0].content)["event"] == "test"


@pytest.mark.parametrize(
    ("url", "allowed"),
    [
        ("https://hooks.example.com/x", True),
        ("http://192.168.1.20:8080/hook", True),
        ("http://10.0.0.5/hook", True),
        ("http://ntfy/scrutineering", True),
        ("http://ntfy.example.com/hook", False),
        ("http://8.8.8.8/hook", False),
        ("ftp://192.168.1.20/hook", False),
    ],
)
def test_webhook_urls_are_https_or_plain_http_on_the_lan(url, allowed):
    env = {"NOTIFICATION_WEBHOOK_URL": url, "NOTIFICATION_WEBHOOK_SECRET": "s"}
    if allowed:
        assert get_settings(env).notification_webhook_url.get_secret_value() == url
    else:
        with pytest.raises(ValueError, match="NOTIFICATION_WEBHOOK_URL"):
            get_settings(env)


def test_the_webhook_needs_a_secret_and_events_must_be_statuses():
    with pytest.raises(ValueError, match="NOTIFICATION_WEBHOOK_SECRET is required"):
        get_settings({"NOTIFICATION_WEBHOOK_URL": URL})
    with pytest.raises(ValueError, match="NOTIFICATION_EVENTS: .*unknown remediation statuses: merged"):
        get_settings({"NOTIFICATION_EVENTS": "ready,merged"})
    assert get_settings({}).notification_events == [
        "proposed",
        "needs_acceptance",
        "ready",
        "published",
        "completed",
        "failed",
    ]


def test_the_settings_know_every_remediation_status():
    assert set(REMEDIATION_STATUSES) == {status.value for status in RemediationStatus}


SLACK_URL = "https://hooks.slack.com/services/T000/B000/XXXX"
SLACK_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "notifications"


@pytest.mark.parametrize("name", ["slack-needs-acceptance", "slack-failed"])
def test_slack_messages_match_the_stored_json(name):
    stored = json.loads((SLACK_FIXTURES / f"{name}.json").read_text())
    assert slack.message(stored["payload"]) == stored["message"]


def test_slack_text_is_escaped_and_the_test_message_is_plain():
    assert slack.escape("<a> & b") == "&lt;a&gt; &amp; b"
    assert slack.message({"event": "test"})["text"].startswith("Scrutineering test notification")


def test_slack_and_the_webhook_each_get_a_row_and_slack_is_unsigned(configured, receiver, monkeypatch):
    monkeypatch.setenv("NOTIFICATION_SLACK_WEBHOOK_URL", SLACK_URL)
    _advance(_remediation(S.VERIFYING), S.READY)

    assert sorted(row.channel for row in _rows()) == ["slack", "webhook"]
    assert delivery.deliver()["sent"] == 2
    to_slack = next(request for request in receiver["requests"] if str(request.url) == SLACK_URL)
    assert webhook.SIGNATURE_HEADER not in to_slack.headers
    assert json.loads(to_slack.content)["text"].startswith("A fix is verified and ready to publish")


def test_slack_alone_needs_no_secret_and_keeps_its_error_code(monkeypatch, receiver):
    monkeypatch.setenv("NOTIFICATION_SLACK_WEBHOOK_URL", SLACK_URL)
    monkeypatch.setattr(outbox, "enqueue_delivery", lambda: None)
    monkeypatch.setattr(
        delivery, "transport", httpx.MockTransport(lambda request: httpx.Response(404, text="no_service"))
    )
    _advance(_remediation(S.VERIFYING), S.READY)
    delivery.deliver()
    [row] = _rows()
    assert (row.channel, row.status, row.last_error) == ("slack", "pending", "HTTP 404 no_service")


def test_receiver_bodies_other_than_short_codes_are_not_kept(configured, monkeypatch):
    body = "<html>error at https://hooks.example.test/scrutineering</html>"
    monkeypatch.setattr(delivery, "transport", httpx.MockTransport(lambda request: httpx.Response(500, text=body)))
    _advance(_remediation(S.VERIFYING), S.READY)
    delivery.deliver()
    assert _rows()[0].last_error == "HTTP 500"


@pytest.mark.parametrize(
    ("url", "allowed"),
    [
        (SLACK_URL, True),
        ("https://hooks.slack.com.evil.example/services/x", False),
        ("http://hooks.slack.com/services/x", False),
        ("https://example.com/services/x", False),
    ],
)
def test_the_slack_url_must_be_a_slack_incoming_webhook(url, allowed):
    env = {"NOTIFICATION_SLACK_WEBHOOK_URL": url}
    if allowed:
        assert get_settings(env).notification_slack_webhook_url.get_secret_value() == url
    else:
        with pytest.raises(ValueError, match="NOTIFICATION_SLACK_WEBHOOK_URL"):
            get_settings(env)
