"""Weekly reports (docs/design/reports-compliance.md, step 1)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from src import signing
from src.api.app import create_app
from src.config import get_settings
from src.db.connection import get_session
from src.db.models import FindingSource, Notification, Report, ScanFinding, Severity, SigningKey
from src.notifications import outbox, slack
from src.remediation import evidence
from src.reports import weekly
from src.scan.celery_app import report_schedule
from tests.test_deployments_api import FIXED, OLD, _completed_remediation, _container, _image, _scan

MONDAY = datetime(2026, 11, 16)  # a Monday
NOW = MONDAY + timedelta(days=7, hours=7)  # the next Monday, 07:00: the weekly run


def _finding(image_id: int, key: str, severity: Severity, *, first_seen, resolved_at=None, reopened_at=None) -> None:
    with get_session() as session:
        session.add(
            ScanFinding(
                image_id=image_id,
                fingerprint=f"fp-{key}",
                vuln_key=key,
                package_name="pkg",
                severity=severity,
                source=FindingSource.TRIVY,
                fix_available=severity == Severity.CRITICAL,
                first_seen=first_seen,
                resolved_at=resolved_at,
                reopened_at=reopened_at,
            )
        )


def test_the_weekly_period_is_the_last_whole_utc_week():
    assert weekly.weekly_period(NOW) == (MONDAY, MONDAY + timedelta(days=7))
    # Sunday night still reports the week before.
    assert weekly.weekly_period(MONDAY + timedelta(days=6, hours=23)) == (MONDAY - timedelta(days=7), MONDAY)
    assert weekly.week_start(MONDAY + timedelta(days=3, hours=5)) == MONDAY


def test_a_week_is_built_once_and_on_demand_reports_are_separate():
    start, end = weekly.weekly_period(NOW)
    assert weekly.build(weekly.WEEKLY, start, end, NOW) is not None
    assert weekly.build(weekly.WEEKLY, start, end, NOW + timedelta(hours=1)) is None
    assert weekly.build(weekly.ON_DEMAND, end, NOW, NOW) is not None
    with get_session() as session:
        assert sorted(kind for (kind,) in session.query(Report.kind).all()) == ["on_demand", "weekly"]


def test_the_sections_count_the_period_and_describe_now():
    app_id = _image()
    other_id = _image("registry:5000/team/other:1.0")
    inside, before = MONDAY + timedelta(days=2), MONDAY - timedelta(days=3)
    _finding(app_id, "new-critical", Severity.CRITICAL, first_seen=inside)
    _finding(app_id, "old-high", Severity.HIGH, first_seen=before)
    _finding(app_id, "fixed-high", Severity.HIGH, first_seen=before, resolved_at=inside)
    _finding(other_id, "reopened-high", Severity.HIGH, first_seen=before, reopened_at=inside)
    _finding(other_id, "other-high-2", Severity.HIGH, first_seen=before)
    _scan(inside, FIXED)
    _scan(inside, None, status="failed")

    start, end = weekly.weekly_period(NOW)
    with get_session() as session:
        document = weekly.build_document(session, weekly.WEEKLY, start, end, NOW)
    assert document["period"] == {
        "start": "2026-11-16T00:00:00Z",
        "end": "2026-11-23T00:00:00Z",
        "generated_at": "2026-11-23T07:00:00Z",
    }
    assert document["posture"]["open"] == {"critical": 1, "high": 3, "medium": 0, "low": 0, "unknown": 0}
    assert document["posture"]["fixable"] == 1
    assert document["changes"]["new"]["critical"] == 1 and document["changes"]["new"]["high"] == 0
    assert document["changes"]["resolved"]["high"] == 1 and document["changes"]["reopened"]["high"] == 1
    assert document["scans"] == {"by_status": {"completed": 1, "failed": 1}, "images_not_scanned": 1}
    assert [item["image"] for item in document["top_images"]] == [
        "registry:5000/team/app:1.0",
        "registry:5000/team/other:1.0",
    ]
    assert document["top_images"][0] == {
        "image_id": app_id,
        "image": "registry:5000/team/app:1.0",
        "critical": 1,
        "high": 1,
    }


def test_fixes_ended_in_the_period_are_listed_with_their_evidence_and_stale_containers():
    image_id = _image()
    rid, _, completed = _completed_remediation(image_id)
    evidence.build_due()
    _container(image_id, "web-1", [OLD], seen=completed + timedelta(minutes=1))
    _container(image_id, "web-2", [FIXED], seen=completed + timedelta(minutes=1))
    now = completed + timedelta(minutes=5)
    start = weekly.week_start(completed)
    with get_session() as session:
        document = weekly.build_document(session, weekly.ON_DEMAND, start, now, now)
        bundle_sha = session.query(evidence.EvidenceBundle.sha256).scalar()
    [item] = document["remediations"]
    assert (item["id"], item["outcome"], item["evidence_sha256"]) == (rid, "completed", bundle_sha)
    assert document["deployments"]["stale_containers"] == [
        {"container": "web-1", "image": "registry:5000/team/app:1.0"}
    ]
    [fix] = document["deployments"]["fixes_not_running"]
    assert (fix["remediation_id"], fix["fixed"], fix["not_fixed"]) == (rid, 1, ["web-1"])
    # Outside the period: not listed.
    with get_session() as session:
        later = weekly.build_document(session, weekly.ON_DEMAND, now, now + timedelta(days=1), now)
    assert later["remediations"] == []


def test_the_stored_bytes_are_canonical_and_signed():
    report = weekly.build(weekly.WEEKLY, *weekly.weekly_period(NOW), NOW)
    assert report.document.encode() == evidence.canonical(json.loads(report.document))
    with get_session() as session:
        pem = session.query(SigningKey).one().public_key_pem
    assert signing.verify(report.document.encode(), report.signature, pem)


def test_weekly_reports_announce_themselves_and_on_demand_ones_do_not(monkeypatch):
    monkeypatch.setenv("NOTIFICATION_WEBHOOK_URL", "https://hooks.example.test/x")
    monkeypatch.setenv("NOTIFICATION_WEBHOOK_SECRET", "secret")
    monkeypatch.setenv("DASHBOARD_PUBLIC_URL", "https://scrutineering.home.lan")
    monkeypatch.setattr(outbox, "enqueue_delivery", lambda: None)
    start, end = weekly.weekly_period(NOW)
    report = weekly.build(weekly.WEEKLY, start, end, NOW)
    weekly.build(weekly.ON_DEMAND, end, NOW, NOW)
    with get_session() as session:
        [row] = session.query(Notification).all()
    assert row.event == "report.ready" and row.remediation_id is None
    assert row.payload["report"]["url"] == f"https://scrutineering.home.lan/reports/{report.id}"
    assert row.payload["report"]["period"]["start"] == "2026-11-16T00:00:00Z"
    message = slack.message(row.payload)
    assert message["text"] == "Scrutineering weekly report, 2026-11-16 to 2026-11-23"


def test_the_schedule_is_cron_or_off():
    assert report_schedule("0 7 * * 1") is not None
    assert report_schedule("off") is None
    assert get_settings({}).report_schedule_cron == "0 7 * * 1"
    with pytest.raises(ValueError, match="REPORT_SCHEDULE_CRON"):
        get_settings({"REPORT_SCHEDULE_CRON": "weekly"})


def _client(monkeypatch, roles: str) -> TestClient:
    monkeypatch.setenv("PYTHON_API_KEY", "reports-key")
    monkeypatch.setenv("DASHBOARD_DEFAULT_ROLES", roles)
    client = TestClient(create_app())
    client.headers["x-api-key"] = "reports-key"
    return client


def test_any_role_reads_reports_and_the_download_is_the_signed_bytes(monkeypatch):
    report = weekly.build(weekly.WEEKLY, *weekly.weekly_period(NOW), NOW)
    client = _client(monkeypatch, "dashboard")
    [listed] = client.get("/api/dashboard/reports").json()["items"]
    assert listed["id"] == report.id and listed["signed"] is True and listed["period_start"].startswith("2026-11-16")
    body = client.get(f"/api/dashboard/reports/{report.id}").json()
    assert body["document"]["schema"] == "scrutineering.report/v1"
    download = client.get(f"/api/dashboard/reports/{report.id}.json")
    assert download.content == report.document.encode()
    assert download.headers["x-scrutineering-report-sha256"] == report.sha256
    assert client.get(f"/api/dashboard/reports/{report.id}.sig").text.strip() == report.signature
    assert client.get("/api/dashboard/reports/999999").status_code == 404


def test_only_admins_build_a_report_on_demand(monkeypatch):
    queued = []
    monkeypatch.setattr(weekly, "queue_on_demand", lambda: queued.append(1) or "task-1")
    assert _client(monkeypatch, "dashboard,security-operator").post("/api/dashboard/reports").status_code == 403
    response = _client(monkeypatch, "admin").post("/api/dashboard/reports")
    assert response.status_code == 202 and response.json()["task_id"] == "task-1" and queued == [1]
