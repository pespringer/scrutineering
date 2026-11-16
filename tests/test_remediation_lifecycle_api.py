"""The remediation lifecycle through the API: one status column, server-verified completion."""

import pytest
from fastapi.testclient import TestClient

from src.api.app import create_app
from src.db.connection import get_session
from src.db.models import Remediation, RemediationStatus, Scan, ScanFinding
from src.db.repositories import RemediationRepository
from src.scan.records import queue_scan
from src.scan.utils.db import persist_findings

API_KEY = "lifecycle-key"
LODASH = {"cve_id": "CVE-2021-23337", "package_name": "lodash", "package_version": "4.17.20", "severity": "high"}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("PYTHON_API_KEY", API_KEY)
    monkeypatch.setenv("DASHBOARD_DEFAULT_ROLES", "dashboard,operator,remediator,security-operator")
    monkeypatch.setenv("REMEDIATION_EXECUTION_ENABLED", "true")
    dispatched = []
    from src.api.routes import remediations

    class FakeTask:
        @staticmethod
        def apply_async(args, queue):
            dispatched.append(args)
            return type("Result", (), {"id": "task-1"})()

    monkeypatch.setattr(remediations, "execute_approved_remediation", FakeTask)
    client = TestClient(create_app())
    client.headers["x-api-key"] = API_KEY
    client.dispatched = dispatched
    return client


@pytest.fixture
def proposal(client):
    scan_id = queue_scan("registry:5000/team/app:1.0", enqueue=lambda *a, **k: None)
    with get_session() as session:
        image_id = session.query(Scan).filter_by(scan_id=scan_id).one().image_id
    persist_findings(scan_id, image_id, [{**LODASH, "package_type": "npm", "fixed_version": "4.17.21"}], "trivy")
    with get_session() as session:
        finding_id = session.query(ScanFinding).filter_by(image_id=image_id).one().id
    assert client.put(f"/api/dashboard/images/{image_id}/source", json={"repository": "app"}).status_code == 200
    created = client.post("/api/dashboard/remediations", json={"image_id": image_id, "finding_ids": [finding_id]})
    assert created.status_code == 201, created.text
    return {"id": created.json()["id"], "image_id": image_id, "finding_id": finding_id}


def _scan_id():
    return queue_scan("registry:5000/team/app:1.0", enqueue=lambda *a, **k: None)


def _status(client, remediation_id):
    return client.get(f"/api/dashboard/remediations/{remediation_id}").json()["status"]


def _force(remediation_id, *statuses):
    with get_session() as session:
        for status in statuses:
            RemediationRepository.update_status(session, remediation_id, status)


def test_proposal_waits_for_approval_and_execution_moves_to_building(client, proposal):
    rid = proposal["id"]
    assert _status(client, rid) == "proposed"
    assert client.post(f"/api/dashboard/remediations/{rid}/execute").status_code == 409

    approved = client.post(f"/api/dashboard/remediations/{rid}/approve")
    assert approved.json()["status"] == "approved"
    assert approved.json()["approved_by"] == "dashboard-service"
    assert client.post(f"/api/dashboard/remediations/{rid}/approve").status_code == 409

    started = client.post(f"/api/dashboard/remediations/{rid}/execute")
    assert started.status_code == 202 and started.json()["status"] == "building"
    assert client.dispatched == [[rid]]
    second = client.post(f"/api/dashboard/remediations/{rid}/execute")
    assert second.status_code == 409 and second.json()["detail"]["status"] == "building"
    events = client.get(f"/api/dashboard/remediations/{rid}/events").json()["events"]
    assert [event["event_type"] for event in events] == ["approved", "execution_queued"]


def test_approval_needs_the_security_operator_role(client, proposal, monkeypatch):
    monkeypatch.setenv("DASHBOARD_DEFAULT_ROLES", "dashboard,remediator")
    assert client.post(f"/api/dashboard/remediations/{proposal['id']}/approve").status_code == 403
    assert client.post("/api/dashboard/remediations/999/approve").status_code in {403, 404}


def test_new_critical_findings_need_explicit_acceptance(client, proposal):
    rid = proposal["id"]
    _force(rid, RemediationStatus.APPROVED, RemediationStatus.BUILDING, RemediationStatus.VERIFYING)
    _force(rid, RemediationStatus.NEEDS_ACCEPTANCE)
    accepted = client.post(f"/api/dashboard/remediations/{rid}/accept")
    assert accepted.status_code == 200 and accepted.json()["status"] == "ready"
    assert client.post(f"/api/dashboard/remediations/{rid}/accept").status_code == 409


def test_failed_remediation_returns_to_approval_on_retry(client, proposal):
    rid = proposal["id"]
    _force(rid, RemediationStatus.APPROVED, RemediationStatus.BUILDING, RemediationStatus.FAILED)
    retried = client.post(f"/api/dashboard/remediations/{rid}/retry").json()
    assert (retried["status"], retried["approved_by"]) == ("proposed", None)


def test_cancelling_releases_the_findings(client, proposal):
    rid = proposal["id"]
    assert client.post(f"/api/dashboard/remediations/{rid}/cancel").json()["status"] == "cancelled"
    with get_session() as session:
        assert session.get(ScanFinding, proposal["finding_id"]).remediation_id is None
    assert client.post(f"/api/dashboard/remediations/{rid}/cancel").status_code == 409


def test_a_clean_complete_rescan_of_the_real_image_completes_a_ready_remediation(client, proposal):
    rid, image_id = proposal["id"], proposal["image_id"]
    _force(rid, RemediationStatus.APPROVED, RemediationStatus.BUILDING, RemediationStatus.VERIFYING)
    _force(rid, RemediationStatus.READY)

    # A partial scan proves nothing; the remediation stays ready.
    persist_findings(_scan_id(), image_id, [], "trivy", reconcile_missing=False)
    assert _status(client, rid) == "ready"
    # Still present (even at another version): not complete.
    still = {**LODASH, "package_version": "4.17.19"}
    persist_findings(_scan_id(), image_id, [still], "trivy", reconcile_missing=True)
    assert _status(client, rid) == "ready"
    # Gone from a complete scan: completed by the server.
    persist_findings(_scan_id(), image_id, [], "trivy", reconcile_missing=True)
    detail = client.get(f"/api/dashboard/remediations/{rid}").json()
    assert detail["status"] == "completed"
    assert detail["resolved_finding_count"] == 1
    assert detail["completed_at"] is not None
    events = [event["event_type"] for event in client.get(f"/api/dashboard/remediations/{rid}/events").json()["events"]]
    assert events[-1] == "completed"


def test_remediations_that_are_not_ready_are_never_completed_by_a_scan(client, proposal):
    persist_findings(_scan_id(), proposal["image_id"], [], "trivy", reconcile_missing=True)
    with get_session() as session:
        assert session.get(Remediation, proposal["id"]).status == RemediationStatus.PROPOSED


def test_a_finding_that_reopens_after_completion_can_be_proposed_again(client, proposal):
    rid, image_id = proposal["id"], proposal["image_id"]
    _force(rid, RemediationStatus.APPROVED, RemediationStatus.BUILDING, RemediationStatus.VERIFYING)
    _force(rid, RemediationStatus.READY)
    persist_findings(_scan_id(), image_id, [], "trivy", reconcile_missing=True)
    assert _status(client, rid) == "completed"

    persist_findings(_scan_id(), image_id, [{**LODASH, "fixed_version": "4.17.21"}], "trivy", reconcile_missing=True)
    again = client.post(
        "/api/dashboard/remediations", json={"image_id": image_id, "finding_ids": [proposal["finding_id"]]}
    )
    assert again.status_code == 201, again.text
