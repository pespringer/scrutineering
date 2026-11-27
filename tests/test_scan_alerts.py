"""`scan.new_critical`: a scan found critical CVEs the image didn't have open (docs/design/scan-alerts.md)."""

from __future__ import annotations

import json

import pytest

from src.db.connection import get_session
from src.db.models import Notification
from src.notifications import slack
from src.notifications.outbox import MAX_CVES
from src.scan.records import create_pending_scan
from src.scan.utils.db import persist_findings
from tests.test_notifications import _block_kit_problems, configured, receiver  # noqa: F401  # fixtures

IMAGE = "registry:5000/shop/api:1.4.2"


def _finding(cve: str, package: str = "openssl", version: str = "3.0.1", severity: str = "critical", **extra) -> dict:
    return {"cve_id": cve, "package_name": package, "package_version": version, "severity": severity, **extra}


def _scan(*findings: dict, complete: bool = True, trigger: str = "scheduled", image: str = IMAGE) -> str:
    with get_session() as session:
        scan = create_pending_scan(session, image, trigger=trigger)
        scan_id, image_id = scan.scan_id, scan.image_id
    persist_findings(scan_id, image_id, list(findings), "trivy", reconcile_missing=complete)
    return scan_id


def _alerts() -> list[dict]:
    with get_session() as session:
        rows = session.query(Notification).filter(Notification.event == "scan.new_critical")
        return [row.payload for row in rows.order_by(Notification.id)]


def _new(*findings: dict, **values) -> list[str] | None:
    """The CVEs a scan's alert lists, or None if it sent none."""
    before = len(_alerts())
    _scan(*findings, **values)
    alerts = _alerts()[before:]
    assert len(alerts) <= 1, "at most one message per scan"
    return alerts[0]["findings"]["cves"] if alerts else None


def test_a_first_scan_announces_its_critical_findings(configured):  # noqa: F811
    scan_id = _scan(
        _finding("CVE-2026-0002", fixed_version="3.0.2"),
        _finding("CVE-2026-0001", "zlib", "1.2"),
        _finding("CVE-2026-0003", severity="high"),
    )
    (alert,) = _alerts()
    assert alert == {
        "event": "scan.new_critical",
        "occurred_at": alert["occurred_at"],
        "scan": {
            "id": scan_id,
            "image": IMAGE,
            "trigger": "scheduled",
            "status": "completed",
            "url": f"https://scrutineering.home.lan/scans/{scan_id}",
        },
        "findings": {
            "new_critical": 2,
            "open_critical": 2,
            "fixable": 1,
            "cve_count": 2,
            "cves": ["CVE-2026-0001", "CVE-2026-0002"],
            "url": alert["findings"]["url"],
        },
    }
    assert alert["findings"]["url"].startswith("https://scrutineering.home.lan/images/")
    assert configured  # delivery was queued once the findings committed


def test_only_what_is_new_is_announced(configured):  # noqa: F811
    old = _finding("CVE-2026-0001")
    assert _new(old) == ["CVE-2026-0001"]
    assert _new(old) is None
    assert _new(old, _finding("CVE-2026-0002")) == ["CVE-2026-0002"]


def test_an_upgrade_that_keeps_the_cve_isnt_news(configured):  # noqa: F811
    _scan(_finding("CVE-2026-0001", "tar", "6.1.11"))
    assert _new(_finding("CVE-2026-0001", "tar", "6.2.1")) is None


def test_the_same_cve_in_another_package_is(configured):  # noqa: F811
    _scan(_finding("CVE-2026-0001", "libssl3"))
    assert _new(_finding("CVE-2026-0001", "libssl3"), _finding("CVE-2026-0001", "libcrypto3")) == ["CVE-2026-0001"]


def test_a_finding_that_comes_back_is_announced_again(configured):  # noqa: F811
    finding = _finding("CVE-2026-0001")
    _scan(finding)
    assert _new(complete=True) is None  # resolved
    assert _new(finding) == ["CVE-2026-0001"]


def test_a_severity_raised_to_critical_is_announced(configured):  # noqa: F811
    _scan(_finding("CVE-2026-0001", severity="high"))
    assert _new(_finding("CVE-2026-0001", severity="critical")) == ["CVE-2026-0001"]


def test_lower_severities_never_are(configured):  # noqa: F811
    assert _new(*(_finding(f"CVE-2026-000{n}", severity=s) for n, s in enumerate(["high", "medium", "low"]))) is None


def test_a_partial_scan_announces_what_it_found_and_says_so(configured):  # noqa: F811
    _scan(_finding("CVE-2026-0001"), complete=False)
    assert _alerts()[0]["scan"]["status"] == "partial"
    # A partial scan resolves nothing, so the next complete one doesn't repeat it.
    assert _new(_finding("CVE-2026-0001")) is None


@pytest.mark.parametrize("trigger", ["manual", "scheduled", "discovery", "post_merge", "retry"])
def test_every_scan_counts_whoever_started_it(configured, trigger):  # noqa: F811
    _scan(_finding("CVE-2026-0001"), trigger=trigger)
    assert _alerts()[0]["scan"]["trigger"] == trigger


def test_images_are_separate(configured):  # noqa: F811
    _scan(_finding("CVE-2026-0001"))
    assert _new(_finding("CVE-2026-0001"), image="registry:5000/shop/api:1.5.0") == ["CVE-2026-0001"]


def test_the_list_is_capped_and_findings_without_a_cve_are_counted(configured):  # noqa: F811
    findings = [_finding(f"CVE-2026-{n:04d}", f"pkg{n}") for n in range(MAX_CVES + 5)]
    _scan(*findings, {"cve_id": None, "package_name": "nocve", "package_version": "1", "severity": "critical"})
    alert = _alerts()[0]["findings"]
    assert (alert["new_critical"], alert["cve_count"], len(alert["cves"])) == (MAX_CVES + 6, MAX_CVES + 5, MAX_CVES)
    assert alert["cves"] == sorted(alert["cves"])


def test_nothing_is_queued_without_a_channel_or_with_the_event_off(monkeypatch, configured):  # noqa: F811
    monkeypatch.setenv("NOTIFICATION_EVENTS", "completed,failed")
    _scan(_finding("CVE-2026-0001"))
    monkeypatch.delenv("NOTIFICATION_WEBHOOK_URL")
    monkeypatch.delenv("NOTIFICATION_EVENTS")
    _scan(_finding("CVE-2026-0002"), image="registry:5000/shop/web:1")
    assert _alerts() == []


def test_nothing_is_queued_when_the_findings_dont_commit(monkeypatch, configured):  # noqa: F811
    from src.notifications import outbox

    def broken(*args, **kwargs):
        raise RuntimeError("the database went away")

    monkeypatch.setattr("src.scan.utils.db.complete_verified_remediations", broken)
    with pytest.raises(RuntimeError):
        _scan(_finding("CVE-2026-0001"))
    assert _alerts() == [] and configured == []
    # And the alert is written in the findings' own transaction, after them.
    calls = []
    monkeypatch.undo()
    monkeypatch.setenv("NOTIFICATION_WEBHOOK_URL", "https://hooks.example.test/scrutineering")
    monkeypatch.setenv("NOTIFICATION_WEBHOOK_SECRET", "notify-secret")
    monkeypatch.setattr(outbox, "enqueue_delivery", lambda: calls.append(1))
    _scan(_finding("CVE-2026-0001"))
    assert len(_alerts()) == 1 and calls == [1]


def test_the_webhook_delivers_it_signed(configured, receiver):  # noqa: F811
    from src.notifications.delivery import deliver

    _scan(_finding("CVE-2026-0001"))
    assert deliver()["sent"] == 1
    (request,) = receiver["requests"]
    assert request.headers["x-scrutineering-event"] == "scan.new_critical"
    assert json.loads(request.content)["findings"]["cves"] == ["CVE-2026-0001"]


def test_without_a_dashboard_url_there_are_no_links(monkeypatch, configured):  # noqa: F811
    monkeypatch.delenv("DASHBOARD_PUBLIC_URL")
    _scan(_finding("CVE-2026-0001"))
    alert = _alerts()[0]
    assert (alert["scan"]["url"], alert["findings"]["url"]) == (None, None)
    message = slack.message(alert)
    assert not any(block["type"] == "actions" for block in message["blocks"])


def test_the_slack_message_stays_within_block_kit_limits_at_the_longest_values():
    payload = {
        "event": "scan.new_critical",
        "scan": {
            "id": "f" * 64,
            "image": "<&>" * 170 + ":" + "t" * 256,
            "trigger": "<" * 32,
            "status": "partial",
            "url": "https://scrutineering.example/" + "p" * 1000,
        },
        "findings": {
            "new_critical": 100_000,
            "open_critical": 100_000,
            "fixable": 100_000,
            "cve_count": 100_000,
            "cves": ["<" * 32] * MAX_CVES,
            "url": "https://scrutineering.example/" + "p" * 1000,
        },
    }
    assert _block_kit_problems(slack.message(payload)) == []
    assert slack.message({**payload, "findings": {**payload["findings"], "new_critical": 1}})["text"].startswith(
        "1 new critical finding in"
    )


# `scan.failed`: an image no person scanned started failing.


def _finished(status: str, trigger: str = "scheduled", image: str = IMAGE) -> str:
    """A scan that ended `completed`, `partial` or `cancelled`, as the worker or the cancel route leaves it."""
    from datetime import datetime, timezone

    with get_session() as session:
        scan = create_pending_scan(session, image, trigger=trigger)
        scan.status = status
        scan.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
        return scan.scan_id


def _fail(trigger: str = "scheduled", error: str = "registry unreachable", image: str = IMAGE) -> str:
    from src.scan.records import mark_scan_failed

    with get_session() as session:
        scan_id = create_pending_scan(session, image, trigger=trigger).scan_id
    with get_session() as session:
        mark_scan_failed(session, scan_id, error)
    return scan_id


def _failures() -> list[dict]:
    with get_session() as session:
        rows = session.query(Notification).filter(Notification.event == "scan.failed")
        return [row.payload for row in rows.order_by(Notification.id)]


def test_a_failed_scheduled_scan_is_announced(configured):  # noqa: F811
    scan_id = _fail(error="trivy: unable to pull the image\nstack trace follows")
    (alert,) = _failures()
    assert alert == {
        "event": "scan.failed",
        "occurred_at": alert["occurred_at"],
        "scan": {
            "id": scan_id,
            "image": IMAGE,
            "trigger": "scheduled",
            "status": "failed",
            "url": f"https://scrutineering.home.lan/scans/{scan_id}",
        },
        "error": "trivy: unable to pull the image",
    }
    assert configured


@pytest.mark.parametrize(
    "trigger, announced",
    [("scheduled", True), ("discovery", True), ("post_merge", True), ("manual", False), ("retry", False)]
    + [("worker", False), (None, False)],
)
def test_only_scans_no_person_started_are_announced(configured, trigger, announced):  # noqa: F811
    _fail(trigger=trigger)
    assert len(_failures()) == (1 if announced else 0)


def test_an_image_that_keeps_failing_sends_one_message(configured):  # noqa: F811
    _fail()
    _fail()
    _fail(trigger="discovery")
    assert len(_failures()) == 1
    _finished("completed")
    _fail()
    _fail()
    assert len(_failures()) == 2, "a success in between starts a new run of failures"


def test_a_partial_scan_counts_as_a_success_and_a_cancelled_one_as_nothing(configured):  # noqa: F811
    _fail()
    _finished("partial")
    _fail()
    assert len(_failures()) == 2, "the partial scan ended the first run of failures"
    _finished("cancelled")
    _fail()
    assert len(_failures()) == 2, "the scan before the cancelled one had failed"


def test_any_earlier_failure_counts_whoever_started_it(configured):  # noqa: F811
    _fail(trigger="manual")
    _fail()
    assert _failures() == []


def test_images_are_separate_for_failures_too(configured):  # noqa: F811
    _fail()
    _fail(image="registry:5000/shop/api:1.5.0")
    assert [alert["scan"]["image"] for alert in _failures()] == [IMAGE, "registry:5000/shop/api:1.5.0"]


def test_a_cancelled_or_already_finished_scan_is_never_announced(configured):  # noqa: F811
    from src.scan.records import mark_scan_failed

    cancelled = _finished("cancelled")
    with get_session() as session:
        mark_scan_failed(session, cancelled, "the worker stopped")
    scan_id = _fail()
    with get_session() as session:
        mark_scan_failed(session, scan_id, "a second report of the same failure")
    assert [alert["scan"]["id"] for alert in _failures()] == [scan_id]


def test_errors_are_cut_to_their_first_line_and_300_characters(configured):  # noqa: F811
    _fail(error="  " + "x" * 400 + "\nsecond line")
    assert _failures()[0]["error"] == "x" * 300
    _finished("completed")
    _fail(error="")
    assert _failures()[1]["error"] is None


def test_a_scan_the_queue_refused_is_announced(configured):  # noqa: F811
    from src.scan.records import queue_scan

    def refuse(*args, **kwargs):
        raise ConnectionError("broker down")

    with pytest.raises(ConnectionError):
        queue_scan(IMAGE, trigger="scheduled", enqueue=refuse)
    assert _failures()[0]["error"] == "scan queue unavailable: broker down"


def test_no_failure_is_queued_without_a_channel_or_with_the_event_off(monkeypatch, configured):  # noqa: F811
    monkeypatch.setenv("NOTIFICATION_EVENTS", "completed,new_critical")
    _fail()
    monkeypatch.delenv("NOTIFICATION_WEBHOOK_URL")
    monkeypatch.delenv("NOTIFICATION_EVENTS")
    _fail(image="registry:5000/shop/web:1")
    assert _failures() == [] and configured == []


def test_invalid_settings_never_stop_the_scan_being_recorded(monkeypatch, configured):  # noqa: F811
    from src.db.models import Scan

    def invalid():
        raise ValueError("invalid configuration: SCANNER_TIMEOUT")

    monkeypatch.setattr("src.notifications.outbox.get_settings", invalid)
    failed = _fail()
    scanned = _scan(_finding("CVE-2026-0001"), image="registry:5000/shop/web:1")
    with get_session() as session:
        statuses = dict(session.query(Scan.scan_id, Scan.status).filter(Scan.scan_id.in_([failed, scanned])))
    assert statuses[failed] == "failed"
    assert _failures() == [] and _alerts() == []


def test_no_failure_is_queued_when_marking_it_rolls_back(configured):  # noqa: F811
    from src.scan.records import mark_scan_failed

    with get_session() as session:
        scan_id = create_pending_scan(session, IMAGE, trigger="scheduled").scan_id
    with pytest.raises(RuntimeError):
        with get_session() as session:
            mark_scan_failed(session, scan_id, "registry unreachable")
            raise RuntimeError("the database went away")
    assert _failures() == [] and configured == []


def test_the_webhook_delivers_the_failure_signed(configured, receiver):  # noqa: F811
    from src.notifications.delivery import deliver

    _fail()
    assert deliver()["sent"] == 1
    (request,) = receiver["requests"]
    assert request.headers["x-scrutineering-event"] == "scan.failed"
    assert json.loads(request.content)["error"] == "registry unreachable"


def test_a_failure_without_a_dashboard_url_has_no_link(monkeypatch, configured):  # noqa: F811
    monkeypatch.delenv("DASHBOARD_PUBLIC_URL")
    _fail()
    alert = _failures()[0]
    assert alert["scan"]["url"] is None
    assert not any(block["type"] == "actions" for block in slack.message(alert)["blocks"])


def test_the_failure_message_stays_within_block_kit_limits_at_the_longest_values():
    payload = {
        "event": "scan.failed",
        "scan": {
            "id": "f" * 64,
            "image": "<&>" * 170 + ":" + "t" * 256,
            "trigger": "<" * 32,
            "status": "failed",
            "url": "https://scrutineering.example/" + "p" * 1000,
        },
        "error": "<&>" * 100,
    }
    assert _block_kit_problems(slack.message(payload)) == []
    assert "no error recorded" in json.dumps(slack.message({**payload, "error": None}))
