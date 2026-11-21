"""Who did what on a remediation, and separation of duties (docs/design/multi-user-roles.md, step 2)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from src.api.app import create_app
from src.config import get_settings
from src.db.connection import get_session
from src.db.models import Remediation, RemediationStatus, Scan, ScanFinding
from src.db.repositories import RemediationRepository
from src.scan.records import queue_scan
from src.scan.utils.db import persist_findings

API_KEY = "sod-key"
SECRET = "sod-proxy-secret"
LODASH = {"cve_id": "CVE-2021-23337", "package_name": "lodash", "package_version": "4.17.20", "severity": "high"}


def _user(sub: str, groups: str = "security") -> dict:
    return {
        "x-dashboard-proxy-secret": SECRET,
        "x-authenticated-sub": sub,
        "x-authenticated-email": f"{sub}@home.lan",
        "x-authenticated-roles": groups,
    }


ALICE, BOB, ADMIN = _user("alice"), _user("bob"), _user("root", "admin")


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("PYTHON_API_KEY", API_KEY)
    monkeypatch.setenv("DASHBOARD_AUTH_MODE", "trusted-proxy")
    monkeypatch.setenv("DASHBOARD_TRUSTED_PROXY_SECRET", SECRET)
    monkeypatch.setenv("DASHBOARD_GROUP_ROLES", "security=security-operator,admin=admin")
    monkeypatch.setenv("REMEDIATION_EXECUTION_ENABLED", "true")
    from src.api.routes import remediations

    class FakeTask:
        @staticmethod
        def apply_async(args, queue):
            return type("Result", (), {"id": "task-1"})()

    monkeypatch.setattr(remediations, "execute_approved_remediation", FakeTask)
    monkeypatch.setattr(remediations, "publish_remediation", FakeTask)
    client = TestClient(create_app())
    client.headers["x-api-key"] = API_KEY
    return client


def _propose(client, headers=ALICE) -> int:
    scan_id = queue_scan("registry:5000/team/app:1.0", enqueue=lambda *a, **k: None)
    with get_session() as session:
        image_id = session.query(Scan).filter_by(scan_id=scan_id).one().image_id
    persist_findings(scan_id, image_id, [{**LODASH, "package_type": "npm", "fixed_version": "4.17.21"}], "trivy")
    with get_session() as session:
        finding_id = session.query(ScanFinding).filter_by(image_id=image_id).one().id
    source = client.put(f"/api/dashboard/images/{image_id}/source", json={"repository": "app"}, headers=headers)
    assert source.status_code == 200, source.text
    created = client.post(
        "/api/dashboard/remediations",
        json={"image_id": image_id, "finding_ids": [finding_id], "proposed_by": "mallory"},
        headers=headers,
    )
    assert created.status_code == 201, created.text
    return created.json()["id"]


def _force(remediation_id, *statuses):
    with get_session() as session:
        for status in statuses:
            RemediationRepository.update_status(session, remediation_id, status)


def _post(client, rid, step, headers):
    return client.post(f"/api/dashboard/remediations/{rid}/{step}", headers=headers)


def test_the_proposer_cannot_approve_and_someone_else_can(client):
    rid = _propose(client)
    refused = _post(client, rid, "approve", ALICE)
    assert refused.status_code == 403
    assert refused.json()["detail"]["code"] == "separate_approver_required"
    approved = _post(client, rid, "approve", BOB)
    assert approved.status_code == 200
    assert (approved.json()["proposed_by"], approved.json()["approved_by"]) == ("alice", "bob")


def test_the_proposer_from_the_body_is_ignored(client):
    rid = _propose(client)
    with get_session() as session:
        assert session.get(Remediation, rid).proposed_by == "alice"


def test_admins_are_bound_too(client):
    rid = _propose(client, ADMIN)
    assert _post(client, rid, "approve", ADMIN).status_code == 403


def test_each_step_records_who_took_it(client, monkeypatch):
    monkeypatch.setattr("src.api.routes.remediations.github_token", lambda: "token")
    monkeypatch.setattr("src.api.routes.remediations.github_repository", lambda repository: ("acme", "app"))
    rid = _propose(client)
    assert _post(client, rid, "approve", BOB).status_code == 200
    assert _post(client, rid, "execute", ALICE).status_code == 202
    _force(rid, RemediationStatus.VERIFYING, RemediationStatus.NEEDS_ACCEPTANCE)
    assert _post(client, rid, "accept", ALICE).json()["detail"]["code"] == "separate_approver_required"
    assert _post(client, rid, "accept", BOB).status_code == 200
    assert _post(client, rid, "publish", ALICE).status_code == 202
    body = client.get(f"/api/dashboard/remediations/{rid}", headers=BOB).json()
    actors = [body[key] for key in ("proposed_by", "approved_by", "executed_by", "accepted_by", "published_by")]
    assert actors == ["alice", "bob", "alice", "bob", "alice"]


def test_a_retry_is_a_new_proposal_by_whoever_retried(client):
    rid = _propose(client)
    assert _post(client, rid, "approve", BOB).status_code == 200
    _force(rid, RemediationStatus.BUILDING, RemediationStatus.FAILED)
    retried = _post(client, rid, "retry", BOB).json()
    assert (retried["proposed_by"], retried["approved_by"], retried["executed_by"]) == ("bob", None, None)
    assert _post(client, rid, "approve", BOB).status_code == 403
    assert _post(client, rid, "approve", ALICE).status_code == 200


def test_remediations_from_before_the_columns_have_no_proposer(client):
    rid = _propose(client)
    with get_session() as session:
        session.get(Remediation, rid).proposed_by = None
    assert _post(client, rid, "approve", ALICE).status_code == 200


def test_off_lets_the_proposer_approve(client, monkeypatch):
    monkeypatch.setenv("REMEDIATION_SEPARATE_APPROVER", "off")
    rid = _propose(client)
    assert client.get("/api/dashboard/permissions", headers=ALICE).json()["separate_approver"] is False
    assert _post(client, rid, "approve", ALICE).status_code == 200


def test_auto_follows_the_auth_mode_and_on_needs_sign_in():
    assert get_settings({"DASHBOARD_AUTH_MODE": "local"}).separate_approver_enabled is False
    proxy = {"DASHBOARD_AUTH_MODE": "trusted-proxy", "DASHBOARD_TRUSTED_PROXY_SECRET": "s"}
    assert get_settings(proxy).separate_approver_enabled is True
    assert get_settings({**proxy, "REMEDIATION_SEPARATE_APPROVER": "off"}).separate_approver_enabled is False
    with pytest.raises(ValueError, match="REMEDIATION_SEPARATE_APPROVER=on needs"):
        get_settings({"DASHBOARD_AUTH_MODE": "local", "REMEDIATION_SEPARATE_APPROVER": "on"})
