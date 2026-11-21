"""People who sign in are recorded for access reviews (docs/design/multi-user-roles.md, step 3)."""

from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from src.api import principals
from src.api.app import create_app
from src.db.connection import get_session
from src.db.models import Principal, ScanFinding
from src.scan.deployments import utcnow
from src.scan.records import queue_scan
from src.scan.utils.db import persist_findings

API_KEY = "people-key"
SECRET = "people-proxy-secret"


def _user(sub: str, groups: str) -> dict:
    return {
        "x-dashboard-proxy-secret": SECRET,
        "x-authenticated-sub": sub,
        "x-authenticated-email": f"{sub}@home.lan",
        "x-authenticated-roles": groups,
    }


@pytest.fixture(autouse=True)
def _fresh_cache():
    principals._recorded.clear()
    yield
    principals._recorded.clear()


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("PYTHON_API_KEY", API_KEY)
    monkeypatch.setenv("DASHBOARD_AUTH_MODE", "trusted-proxy")
    monkeypatch.setenv("DASHBOARD_TRUSTED_PROXY_SECRET", SECRET)
    monkeypatch.setenv("DASHBOARD_GROUP_ROLES", "ops=operator,admins=admin")
    client = TestClient(create_app())
    client.headers["x-api-key"] = API_KEY
    return client


def _people():
    with get_session() as session:
        return {p.subject: (p.email, p.roles, p.first_seen_at, p.last_seen_at) for p in session.query(Principal)}


def test_signing_in_records_the_person_with_their_roles(client):
    assert client.get("/api/dashboard/session", headers=_user("alice", "ops")).status_code == 200
    assert _people()["alice"][:2] == ("alice@home.lan", ["operator"])


def test_someone_without_a_role_is_recorded_too(client):
    assert client.get("/api/dashboard/session", headers=_user("eve", "family")).status_code == 403
    assert _people()["eve"][1] == []


def test_api_key_sessions_are_not_people(client, monkeypatch):
    monkeypatch.setenv("DASHBOARD_AUTH_MODE", "local")
    assert client.get("/api/dashboard/session").status_code == 200
    assert _people() == {}


def test_a_person_is_written_at_most_hourly_unless_their_roles_change():
    now = utcnow()
    principals.seen("bob", "bob@home.lan", ["operator"])
    first = _people()["bob"][3]
    assert not principals.due("bob", "bob@home.lan", ["operator"], first + timedelta(minutes=59))
    assert principals.due("bob", "bob@home.lan", ["operator"], first + timedelta(hours=1))
    assert principals.due("bob", "bob@home.lan", ["operator", "remediator"], first + timedelta(minutes=1))
    principals.record("bob", "bob@home.lan", ["remediator"], now + timedelta(hours=2))
    email, roles, first_seen, last_seen = _people()["bob"]
    assert (roles, first_seen, last_seen) == (["remediator"], first, now + timedelta(hours=2))


def test_people_unseen_for_a_year_are_pruned():
    now = utcnow()
    principals.record("old", None, [], now - timedelta(days=366))
    principals.record("recent", None, [], now - timedelta(days=364))
    assert principals.prune(now) == 1
    assert set(_people()) == {"recent"}


def test_the_people_page_is_admin_only(client):
    client.get("/api/dashboard/session", headers=_user("alice", "ops"))
    assert client.get("/api/dashboard/people", headers=_user("alice", "ops")).status_code == 403
    body = client.get("/api/dashboard/people", headers=_user("root", "admins")).json()
    assert [(p["subject"], p["roles"]) for p in body["items"]][-1] == ("alice", ["operator"])
    assert {p["subject"] for p in body["items"]} == {"alice", "root"}


def test_assignees_list_people_without_their_roles(client):
    client.get("/api/dashboard/session", headers=_user("alice", "ops"))
    body = client.get("/api/dashboard/people/assignees", headers=_user("alice", "ops")).json()
    assert body["items"] == [{"subject": "alice", "email": "alice@home.lan"}]


def _finding_id() -> int:
    scan_id = queue_scan("registry:5000/team/app:1.0", enqueue=lambda *a, **k: None)
    with get_session() as session:
        from src.db.models import Scan

        image_id = session.query(Scan).filter_by(scan_id=scan_id).one().image_id
    finding = {"cve_id": "CVE-1", "package_name": "x", "package_version": "1", "severity": "high"}
    persist_findings(scan_id, image_id, [finding], "trivy")
    with get_session() as session:
        return session.query(ScanFinding).filter_by(image_id=image_id).one().id


def test_findings_are_assigned_only_to_known_people_with_sign_in(client):
    finding_id = _finding_id()
    alice = _user("alice", "ops")
    client.get("/api/dashboard/session", headers=alice)
    unknown = {"finding_ids": [finding_id], "assignee": "mallory"}
    assert client.post("/api/dashboard/findings/bulk-assign", json=unknown, headers=alice).status_code == 422
    known = {"finding_ids": [finding_id], "assignee": "alice"}
    assert client.post("/api/dashboard/findings/bulk-assign", json=known, headers=alice).json()["count"] == 1
    cleared = {"finding_ids": [finding_id], "assignee": None}
    assert client.post("/api/dashboard/findings/bulk-assign", json=cleared, headers=alice).json()["count"] == 1


def test_local_mode_keeps_free_text_assignment(client, monkeypatch):
    monkeypatch.setenv("DASHBOARD_AUTH_MODE", "local")
    monkeypatch.setenv("DASHBOARD_DEFAULT_ROLES", "operator")
    payload = {"finding_ids": [_finding_id()], "assignee": "alice"}
    assert client.post("/api/dashboard/findings/bulk-assign", json=payload).json()["count"] == 1
