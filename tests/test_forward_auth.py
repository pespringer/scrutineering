"""Sign-in through a forward-auth proxy: groups map to roles, and trusted-proxy mode never falls back.

See docs/design/forward-auth.md. The dashboard forwards the proxy's verified user as
`x-authenticated-*` headers with `x-dashboard-proxy-secret`; the API decides the roles.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from src.api.app import create_app
from src.api.auth import groups_from_header, roles_for_groups
from src.config import get_settings
from src.db.connection import get_session
from src.db.models import AuditLog
from tests.test_remediation_planning_api import image  # noqa: F401  # fixture

API_KEY = "auth-key"
SECRET = "proxy-secret"


def _client(monkeypatch, mode: str = "trusted-proxy", group_roles: str = "") -> TestClient:
    monkeypatch.setenv("PYTHON_API_KEY", API_KEY)
    monkeypatch.setenv("DASHBOARD_DEFAULT_ROLES", "dashboard,operator,remediator,security-operator")
    monkeypatch.setenv("DASHBOARD_AUTH_MODE", mode)
    monkeypatch.setenv("DASHBOARD_TRUSTED_PROXY_SECRET", SECRET)
    monkeypatch.setenv("DASHBOARD_GROUP_ROLES", group_roles)
    client = TestClient(create_app())
    client.headers["x-api-key"] = API_KEY  # the dashboard server always sends it
    return client


def _user(groups: str, sub: str = "alice", email: str | None = "alice@home.lan", secret: str = SECRET) -> dict:
    headers = {"x-dashboard-proxy-secret": secret, "x-authenticated-sub": sub, "x-authenticated-roles": groups}
    if email:
        headers["x-authenticated-email"] = email
    return headers


def test_groups_map_to_the_union_of_their_roles():
    mapping = {"ops": ["operator"], "security": ["security-operator", "remediator"]}
    assert roles_for_groups(["ops", "security", "family"], mapping) == ["operator", "security-operator", "remediator"]
    assert roles_for_groups(["family"], mapping) == []
    assert roles_for_groups(["admin", "admin", "x"], {}) == ["admin", "x"]  # no mapping: group names are roles
    assert groups_from_header(" ops, ,security ") == ["ops", "security"]


def test_the_mapping_and_mode_are_validated():
    settings = get_settings({"DASHBOARD_GROUP_ROLES": "ops = operator, security=security-operator,ops=remediator"})
    assert settings.group_role_map == {"ops": ["operator", "remediator"], "security": ["security-operator"]}
    with pytest.raises(ValueError, match="DASHBOARD_GROUP_ROLES: .*unknown role 'superuser'"):
        get_settings({"DASHBOARD_GROUP_ROLES": "ops=superuser"})
    with pytest.raises(ValueError, match="not a group=role pair"):
        get_settings({"DASHBOARD_GROUP_ROLES": "ops"})
    with pytest.raises(ValueError, match="DASHBOARD_TRUSTED_PROXY_SECRET is required"):
        get_settings({"DASHBOARD_AUTH_MODE": "trusted-proxy"})
    with pytest.raises(ValueError, match="DASHBOARD_AUTH_MODE"):
        get_settings({"DASHBOARD_AUTH_MODE": "oidc"})


def test_a_signed_in_user_gets_the_roles_of_their_groups(monkeypatch):
    client = _client(monkeypatch, group_roles="ops=operator,security=security-operator")
    session = client.get("/api/dashboard/session", headers=_user("ops,security,family")).json()
    assert session["subject"] == "alice" and session["email"] == "alice@home.lan"
    assert session["auth_method"] == "oidc_proxy"
    assert session["roles"] == ["operator", "security-operator"]


def test_without_a_mapping_group_names_are_role_names(monkeypatch):
    client = _client(monkeypatch)
    assert client.get("/api/dashboard/session", headers=_user("remediator")).json()["roles"] == ["remediator"]


def test_trusted_proxy_mode_never_falls_back_to_the_default_roles(monkeypatch):
    client = _client(monkeypatch, group_roles="ops=operator")
    response = client.get("/api/dashboard/session")  # API key, no user
    assert response.status_code == 401 and response.json() == {"error": "identity_required"}
    forged = client.get("/api/dashboard/session", headers=_user("ops", secret="guessed"))
    assert forged.status_code == 401
    no_user = client.get("/api/dashboard/session", headers={"x-dashboard-proxy-secret": SECRET})
    assert no_user.status_code == 401
    assert client.get("/health").status_code == 200  # public paths are unchanged


def test_a_signed_in_user_with_no_mapped_role_is_refused(monkeypatch):
    client = _client(monkeypatch, group_roles="ops=operator")
    for groups in ("family", ""):
        response = client.get("/api/dashboard/posture/summary", headers=_user(groups))
        assert response.status_code == 403 and response.json() == {"error": "no_role"}, groups


def test_roles_still_gate_each_route(monkeypatch):
    client = _client(monkeypatch, group_roles="viewers=dashboard,security=security-operator")
    assert client.get("/api/dashboard/notifications", headers=_user("viewers")).status_code == 403
    assert client.get("/api/dashboard/notifications", headers=_user("security")).status_code == 200


def test_local_mode_is_unchanged(monkeypatch):
    client = _client(monkeypatch, mode="local")
    session = client.get("/api/dashboard/session").json()
    assert session["subject"] == "dashboard-service" and session["auth_method"] == "api_key"
    assert session["roles"] == ["dashboard", "operator", "remediator", "security-operator"]


def test_audit_entries_name_the_user_and_their_email(monkeypatch):
    from src.scan import tasks

    monkeypatch.setattr(tasks, "enqueue_scan", lambda target, **kw: None)
    client = _client(monkeypatch, group_roles="ops=operator")
    response = client.post(
        "/api/dashboard/scans", json={"image_name": "registry:5000/team/app:1.0"}, headers=_user("ops")
    )
    assert response.status_code in (200, 202), response.text
    with get_session() as session:
        entry = session.query(AuditLog).filter(AuditLog.actor == "alice").one()
        assert entry.actor_kind == "user"
        assert entry.detail["actor_email"] == "alice@home.lan"


def test_mapped_roles_carry_the_remediation_loop(monkeypatch, image):  # noqa: F811
    """A remediator proposes; only the security group may approve, and the audit names who did what."""
    client = _client(monkeypatch, group_roles="devs=remediator,security=security-operator")
    image_id, ids = image
    dev, security = _user("devs", sub="dev", email="dev@home.lan"), _user("security", sub="sec", email=None)

    connected = client.put(f"/api/dashboard/images/{image_id}/source", json={"repository": "team-app"}, headers=dev)
    assert connected.status_code == 200, connected.text
    body = {"image_id": image_id, "finding_ids": [ids["lodash-trivy"]]}
    created = client.post("/api/dashboard/remediations", json=body, headers=dev)
    assert created.status_code == 201, created.text
    remediation_id = created.json()["id"]

    assert client.post(f"/api/dashboard/remediations/{remediation_id}/approve", headers=dev).status_code == 403
    approved = client.post(f"/api/dashboard/remediations/{remediation_id}/approve", headers=security)
    assert approved.status_code == 200, approved.text
    with get_session() as session:
        actors = {entry.actor for entry in session.query(AuditLog).filter(AuditLog.entity_type == "remediation")}
    assert actors == {"dev", "sec"}
