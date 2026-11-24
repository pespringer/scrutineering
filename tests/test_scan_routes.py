"""Scan history, scan controls and per-scan findings, through the dashboard API."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from src.api.app import create_app
from src.db.connection import get_session
from src.db.models import AuditLog, FindingObservation, FindingSource, Scan, ScanFinding, Severity
from src.scan.records import create_pending_scan

API_KEY = "scan-routes-key"


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


@pytest.fixture
def revoked(monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(
        "src.api.routes.scans.celery_app.control.revoke", lambda scan_id, terminate=False: calls.append(scan_id)
    )
    return calls


def _client(monkeypatch, roles: str = "operator") -> TestClient:
    monkeypatch.setenv("PYTHON_API_KEY", API_KEY)
    monkeypatch.setenv("DASHBOARD_DEFAULT_ROLES", roles)
    client = TestClient(create_app())
    client.headers["x-api-key"] = API_KEY
    return client


def _scan(target: str, status: str = "completed", *, started: datetime | None = None, archived=False) -> str:
    with get_session() as session:
        scan = create_pending_scan(session, target)
        scan.status, scan.started_at, scan.archived = status, started or _now(), archived
        return scan.scan_id


def _status(scan_id: str) -> str:
    with get_session() as session:
        return session.query(Scan).filter_by(scan_id=scan_id).one().status


def _audit_actions() -> list[str]:
    with get_session() as session:
        return [record.detail.get("action") for record in session.query(AuditLog).order_by(AuditLog.id)]


def test_history_filters_by_status_and_search_and_hides_archived_scans(monkeypatch):
    client = _client(monkeypatch)
    now = _now()
    api = _scan("registry:5000/team/api:1", "completed", started=now - timedelta(minutes=2))
    failed = _scan("registry:5000/team/web:1", "failed", started=now - timedelta(minutes=1))
    archived = _scan("registry:5000/team/api:0", "completed", started=now, archived=True)

    body = client.get("/api/dashboard/scans").json()
    assert [item["scan_id"] for item in body["items"]] == [failed, api]
    assert body["total"] == 2

    assert [i["scan_id"] for i in client.get("/api/dashboard/scans?status=FAILED").json()["items"]] == [failed]
    assert [i["scan_id"] for i in client.get("/api/dashboard/scans?search=api").json()["items"]] == [api]
    everything = client.get("/api/dashboard/scans?include_archived=true&status=all").json()
    assert {item["scan_id"] for item in everything["items"]} == {api, failed, archived}


def test_history_rejects_an_unknown_status(monkeypatch):
    response = _client(monkeypatch).get("/api/dashboard/scans?status=finished")
    assert (response.status_code, response.json()["detail"]) == (400, "invalid scan status")


def test_health_summarises_recent_scans(monkeypatch):
    client = _client(monkeypatch)
    _scan("registry:5000/team/api:1", "completed")
    _scan("registry:5000/team/api:2", "failed")
    body = client.get("/api/dashboard/scans/health").json()
    assert body["total"] == 2
    assert body["by_status"] == {"completed": 1, "failed": 1}
    assert body["degraded"] is True


def test_cancelling_a_running_scan_records_it_and_revokes_the_task(monkeypatch, revoked):
    client = _client(monkeypatch)
    scan_id = _scan("registry:5000/team/api:1", "running")

    response = client.post(f"/api/dashboard/scans/{scan_id}/cancel")

    assert response.json() == {"scan_id": scan_id, "status": "cancelled"}
    assert _status(scan_id) == "cancelled"
    assert revoked == [scan_id]
    assert _audit_actions() == ["cancel_scan"]


def test_cancelling_a_finished_scan_changes_nothing(monkeypatch, revoked):
    client = _client(monkeypatch)
    scan_id = _scan("registry:5000/team/api:1", "completed")

    response = client.post(f"/api/dashboard/scans/{scan_id}/cancel")

    assert response.status_code == 200 and response.json()["status"] == "completed"
    assert revoked == [] and _audit_actions() == []


def test_cancelling_an_unknown_scan_is_404(monkeypatch, revoked):
    response = _client(monkeypatch).post("/api/dashboard/scans/nope/cancel")
    assert (response.status_code, response.json()["detail"]) == (404, "scan_not_found")


def test_scan_controls_need_the_operator_role(monkeypatch, revoked):
    client = _client(monkeypatch, roles="dashboard")
    scan_id = _scan("registry:5000/team/api:1", "running")
    for path, body in (
        (f"/scans/{scan_id}/cancel", None),
        ("/scans/bulk-cancel", {"ids": [scan_id]}),
        ("/scans/bulk-archive", {"ids": [scan_id]}),
        ("/scans/bulk-retry", {"ids": [scan_id]}),
        ("/scans", {"image_name": "registry:5000/team/api:1"}),
    ):
        assert client.post(f"/api/dashboard{path}", json=body).status_code == 403, path
    assert _status(scan_id) == "running" and revoked == []


def test_bulk_cancel_stops_only_unfinished_scans(monkeypatch, revoked):
    client = _client(monkeypatch)
    pending = _scan("registry:5000/team/api:1", "pending")
    running = _scan("registry:5000/team/api:2", "running")
    done = _scan("registry:5000/team/api:3", "completed")

    body = client.post("/api/dashboard/scans/bulk-cancel", json={"ids": [pending, running, done, "missing"]}).json()

    assert sorted(body["cancelled"]) == sorted([pending, running]) and body["count"] == 2
    assert (_status(pending), _status(running), _status(done)) == ("cancelled", "cancelled", "completed")
    assert sorted(revoked) == sorted([pending, running])


def test_bulk_archive_skips_scans_still_in_progress(monkeypatch):
    client = _client(monkeypatch)
    done = _scan("registry:5000/team/api:1", "completed")
    running = _scan("registry:5000/team/api:2", "running")

    body = client.post("/api/dashboard/scans/bulk-archive", json={"ids": [done, running]}).json()

    assert body["archived"] == [done]
    assert [item["scan_id"] for item in client.get("/api/dashboard/scans").json()["items"]] == [running]


def test_bulk_retry_queues_failed_and_cancelled_scans_again(monkeypatch):
    client = _client(monkeypatch)
    failed = _scan("registry:5000/team/api:1", "failed")
    cancelled = _scan("registry:5000/team/api:2", "cancelled")
    done = _scan("registry:5000/team/api:3", "completed")
    queued: list[tuple[str, str]] = []

    def fake_queue(target, *, priority="normal", trigger="manual", **_):
        queued.append((target, trigger))
        return f"retry-{len(queued)}"

    monkeypatch.setattr("src.api.routes.scans.queue_scan", fake_queue)

    body = client.post("/api/dashboard/scans/bulk-retry", json={"ids": [failed, cancelled, done]})

    assert body.status_code == 202
    retried = {item["source_scan_id"]: item["image_name"] for item in body.json()["retried"]}
    assert retried == {failed: "registry:5000/team/api:1", cancelled: "registry:5000/team/api:2"}
    assert {trigger for _, trigger in queued} == {"retry"}
    assert _audit_actions() == ["retry_scan", "retry_scan"]


def test_bulk_retry_skips_a_scan_that_cannot_be_queued(monkeypatch):
    client = _client(monkeypatch)
    failed = _scan("registry:5000/team/api:1", "failed")

    def broken_queue(*_args, **_kwargs):
        raise ConnectionError("broker down")

    monkeypatch.setattr("src.api.routes.scans.queue_scan", broken_queue)

    body = client.post("/api/dashboard/scans/bulk-retry", json={"ids": [failed]}).json()
    assert (body["retried"], body["count"]) == ([], 0)
    assert _audit_actions() == []


def test_starting_a_scan_reports_an_unavailable_queue(monkeypatch):
    client = _client(monkeypatch)

    def broken_queue(*_args, **_kwargs):
        raise ConnectionError("broker down")

    monkeypatch.setattr("src.api.routes.scans.queue_scan", broken_queue)

    response = client.post("/api/dashboard/scans", json={"image_name": "registry:5000/team/api:1"})
    assert (response.status_code, response.json()["detail"]) == (503, "scan_queue_unavailable")
    assert _audit_actions() == []


def test_starting_a_scan_records_who_started_it(monkeypatch):
    client = _client(monkeypatch)
    monkeypatch.setattr("src.api.routes.scans.queue_scan", lambda target, **_: "scan-new")

    response = client.post("/api/dashboard/scans", json={"image_name": "registry:5000/team/api:1", "priority": "high"})

    assert response.status_code == 202
    assert response.json() == {
        "scan_id": "scan-new",
        "task_id": "scan-new",
        "image_name": "registry:5000/team/api:1",
        "status": "pending",
    }
    assert _audit_actions() == ["start_scan"]


def test_scan_status_of_an_unknown_scan_is_404(monkeypatch):
    client = _client(monkeypatch)
    assert client.get("/api/dashboard/scans/nope").status_code == 404
    assert client.get("/api/dashboard/scans/nope/findings").status_code == 404


def _observe(scan_id: str, image_id: int, cve: str, severity: Severity, fixed: str | None, resolved=False) -> int:
    with get_session() as session:
        finding = ScanFinding(
            image_id=image_id,
            fingerprint=f"fp-{cve}",
            vuln_key=f"{cve}:pkg",
            cve_id=cve,
            package_name="pkg",
            package_version="1.0",
            severity=severity,
            fixed_version=fixed,
            fix_available=fixed is not None,
            source=FindingSource.TRIVY,
            resolved_at=_now() if resolved else None,
        )
        session.add(finding)
        session.flush()
        session.add(FindingObservation(scan_id=scan_id, finding_id=finding.id, severity=severity, fixed_version=fixed))
        return finding.id


def test_scan_findings_filter_by_severity_and_fixability(monkeypatch):
    client = _client(monkeypatch)
    scan_id = _scan("registry:5000/team/api:1", "completed")
    with get_session() as session:
        image_id = session.query(Scan).filter_by(scan_id=scan_id).one().image_id
    critical = _observe(scan_id, image_id, "CVE-1", Severity.CRITICAL, "1.1")
    high = _observe(scan_id, image_id, "CVE-2", Severity.HIGH, None)
    fixed_since = _observe(scan_id, image_id, "CVE-3", Severity.HIGH, "1.2", resolved=True)

    def ids(query: str = "") -> list[int]:
        body = client.get(f"/api/dashboard/scans/{scan_id}/findings{query}").json()
        assert body["image_id"] == image_id
        return sorted(item["id"] for item in body["items"])

    assert ids() == sorted([critical, high, fixed_since])
    assert ids("?severity=high") == sorted([high, fixed_since])
    assert ids("?fixable_only=true") == [critical]
    response = client.get(f"/api/dashboard/scans/{scan_id}/findings?severity=urgent")
    assert response.status_code == 400
