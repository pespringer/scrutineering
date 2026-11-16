"""Connecting an image to the repository it is built from."""

import pytest
from fastapi.testclient import TestClient

from src.api.app import create_app
from src.db.connection import get_session
from src.db.models import AuditLog
from src.remediation.sources import SourceError, SourceSettings
from src.scan.records import queue_scan

API_KEY = "sources-key"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("PYTHON_API_KEY", API_KEY)
    monkeypatch.setenv("DASHBOARD_DEFAULT_ROLES", "dashboard,operator,remediator,security-operator")
    client = TestClient(create_app())
    client.headers["x-api-key"] = API_KEY
    return client


@pytest.fixture
def image_id():
    scan_id = queue_scan("registry:5000/team/app:1.0", enqueue=lambda *a, **k: None)
    with get_session() as session:
        from src.db.models import Scan

        return session.query(Scan).filter_by(scan_id=scan_id).one().image_id


def test_connect_read_update_and_remove_a_source(client, image_id):
    assert client.get(f"/api/dashboard/images/{image_id}/source").json()["source"] is None

    body = {"repository": "team-app", "dockerfile_path": "docker/Dockerfile", "build_args": {"NODE_ENV": "production"}}
    saved = client.put(f"/api/dashboard/images/{image_id}/source", json=body)
    assert saved.status_code == 200, saved.text
    source = saved.json()["source"]
    assert source["repository"] == "team-app"
    assert (source["ref"], source["build_context"]) == ("HEAD", ".")
    assert source["build_args"] == {"NODE_ENV": "production"}
    assert source["updated_by"] == "dashboard-service"

    detail = client.get(f"/api/dashboard/images/{image_id}").json()["image"]
    assert detail["source"]["dockerfile_path"] == "docker/Dockerfile"

    updated = client.put(
        f"/api/dashboard/images/{image_id}/source",
        json={"repository": "https://git.example/team/app.git", "ref": "main"},
    )
    assert updated.json()["source"]["repository"] == "https://git.example/team/app.git"

    assert client.delete(f"/api/dashboard/images/{image_id}/source").json()["source"] is None
    assert client.get(f"/api/dashboard/images/{image_id}").json()["image"]["source"] is None
    with get_session() as session:
        actions = [row.detail.get("action") for row in session.query(AuditLog).order_by(AuditLog.id)]
    assert actions[-3:] == ["image_source_set", "image_source_set", "image_source_removed"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("repository", "../outside"),
        ("repository", "/etc"),
        ("repository", "http://insecure.example/app.git"),
        ("repository", "https://user:token@git.example/app.git"),
        ("dockerfile_path", "../Dockerfile"),
        ("build_context", "/abs"),
        ("ref", "--upload-pack=evil"),
    ],
)
def test_unsafe_source_settings_are_rejected(client, image_id, field, value):
    body = {"repository": "team-app", field: value}
    response = client.put(f"/api/dashboard/images/{image_id}/source", json=body)
    assert response.status_code == 422, response.text


def test_changing_a_source_requires_a_remediation_role(client, image_id, monkeypatch):
    monkeypatch.setenv("DASHBOARD_DEFAULT_ROLES", "dashboard,operator")
    response = client.put(f"/api/dashboard/images/{image_id}/source", json={"repository": "team-app"})
    assert response.status_code == 403


def test_unknown_image_returns_404(client):
    assert client.put("/api/dashboard/images/999/source", json={"repository": "x"}).status_code == 404


def test_local_paths_stay_inside_the_sources_root(tmp_path):
    settings = SourceSettings.validated(repository="team/app")
    assert settings.local_path(tmp_path) == (tmp_path / "team/app").resolve()
    assert not settings.is_remote
    with pytest.raises(SourceError):
        SourceSettings.validated(repository="https://git.example/app.git").local_path(tmp_path)


def test_build_arguments_and_test_command_are_validated():
    with pytest.raises(SourceError):
        SourceSettings.validated(repository="app", build_args={"bad name": "x"})
    with pytest.raises(SourceError):
        SourceSettings.validated(repository="app", test_command=["npm", ""])
    ok = SourceSettings.validated(repository="app", test_command=["npm", "test"])
    assert ok.test_command == ["npm", "test"]
