"""Deleting tags from the bundled registry (docs/design/registry-management.md), against a fake registry."""

from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from src.api.app import create_app
from src.db.connection import get_session
from src.db.models import AuditLog, Deployment, Image, Remediation, RemediationStatus, Scan, ScanFinding
from src.db.models import FindingSource, Severity
from src.scan.deployments import utcnow
from src.scan.records import create_pending_scan, get_or_create_image, scan_identity
from tests.fake_registry import HOST, FakeRegistry

API_KEY = "registry-key"
PUBLIC = "localhost:5000"
OTHER = "sha256:" + "9" * 64
S = RemediationStatus


@pytest.fixture
def registry(monkeypatch) -> FakeRegistry:
    fake = FakeRegistry()
    monkeypatch.setenv("LOCAL_REGISTRY_HOST", HOST)
    monkeypatch.setenv("LOCAL_REGISTRY_PUBLIC_HOST", PUBLIC)
    monkeypatch.setenv("REGISTRY_INSECURE", "true")
    monkeypatch.setattr("src.scan.registry_catalog._open", fake)
    return fake


def _client(monkeypatch, roles: str = "security-operator") -> TestClient:
    monkeypatch.setenv("PYTHON_API_KEY", API_KEY)
    monkeypatch.setenv("DASHBOARD_DEFAULT_ROLES", roles)
    client = TestClient(create_app())
    client.headers["x-api-key"] = API_KEY
    return client


def _post(client: TestClient, *items: tuple[str, str, str]):
    body = {"items": [{"repository": r, "tag": t, "digest": d} for r, t, d in items]}
    return client.post("/api/dashboard/registry/tags/delete", json=body)


def _delete(monkeypatch, registry: FakeRegistry, tag: str = "1", repository: str = "team/api") -> dict:
    digest = registry.tags[repository][tag]
    response = _post(_client(monkeypatch), (repository, tag, digest))
    assert response.status_code == 200, response.text
    return response.json()["results"][0]


def _refused(monkeypatch, registry, code: str, tag: str = "1", repository: str = "team/api") -> str:
    result = _delete(monkeypatch, registry, tag, repository)
    assert (result["deleted"], result["code"]) == (False, code), result
    assert tag in registry.tags[repository]
    assert _audit() == []
    return result["reason"]


def _audit() -> list[AuditLog]:
    with get_session() as session:
        records = session.query(AuditLog).order_by(AuditLog.id).all()
        session.expunge_all()
        return records


def _image(reference: str = f"{HOST}/team/api:1") -> int:
    with get_session() as session:
        return get_or_create_image(session, scan_identity(reference)).id


def _remediation(reference: str, status: RemediationStatus, **values) -> int:
    with get_session() as session:
        image = get_or_create_image(session, scan_identity(reference))
        row = Remediation(image_id=image.id, status=status, **values)
        session.add(row)
        session.flush()
        return row.id


def _container(image_ref: str, digests: list[str] | None = None, *, gone=False, seen_days_ago=0) -> None:
    seen = utcnow() - timedelta(days=seen_days_ago)
    with get_session() as session:
        image = get_or_create_image(session, scan_identity(image_ref))
        session.add(
            Deployment(
                container_id=f"c-{image_ref}",
                name="web-1",
                image_ref=image_ref,
                image_id=image.id,
                running_digests=digests or [],
                first_seen_at=seen,
                last_seen_at=seen,
                gone_at=seen if gone else None,
            )
        )


# Deleting


def test_deleting_removes_the_tag_archives_the_image_and_is_audited(monkeypatch, registry):
    digest = registry.image({"a": 1})
    registry.tag("team/api", "1", digest)
    image_id = _image()
    with get_session() as session:
        session.add(
            ScanFinding(
                image_id=image_id,
                fingerprint="fp",
                vuln_key="CVE-1:pkg",
                cve_id="CVE-1",
                package_name="pkg",
                package_version="1",
                severity=Severity.HIGH,
                source=FindingSource.TRIVY,
            )
        )
        create_pending_scan(session, f"{HOST}/team/api:1").status = "completed"

    result = _delete(monkeypatch, registry)

    assert result == {"repository": "team/api", "tag": "1", "deleted": True, "code": None, "reason": None}
    assert registry.tags["team/api"] == {}
    with get_session() as session:
        assert session.get(Image, image_id).active is False
        assert session.query(Scan).count() == 1 and session.query(ScanFinding).count() == 1
    (record,) = _audit()
    assert (record.event_type.value, record.entity_type, record.entity_id) == ("config_changed", "registry_tag", digest)
    assert record.detail["action"] == "delete_registry_tag"
    assert (record.detail["image"], record.detail["archived_image_ids"]) == (f"{HOST}/team/api:1", [image_id])


def test_tags_sharing_the_image_are_kept(monkeypatch, registry):
    digest = registry.image({"a": 1})
    for tag in ("1", "2"):
        registry.tag("team/api", tag, digest)
    kept = _image(f"{HOST}/team/api:2")
    assert _delete(monkeypatch, registry)["deleted"]
    assert registry.tags["team/api"] == {"2": digest}
    with get_session() as session:
        assert session.get(Image, kept).active is True


def test_both_names_of_the_image_are_archived_but_not_docker_hubs(monkeypatch, registry):
    registry.tag("team/api", "1", registry.image({"a": 1}))
    ours = [_image(), _image(f"{PUBLIC}/team/api:1")]
    hub = _image("team/api:1")
    assert _delete(monkeypatch, registry)["deleted"]
    with get_session() as session:
        assert [session.get(Image, image_id).active for image_id in (*ours, hub)] == [False, False, True]


def test_an_untracked_tag_can_be_deleted(monkeypatch, registry):
    registry.tag("team/api", "1", registry.image({"a": 1}))
    assert _delete(monkeypatch, registry)["deleted"]
    assert _audit()[0].detail["archived_image_ids"] == []


def test_each_item_has_its_own_result(monkeypatch, registry):
    one, two = registry.image({"a": 1}), registry.image({"b": 1})
    registry.tag("team/api", "1", one)
    registry.tag("team/api", "2", two)
    _remediation(f"{HOST}/team/api:2", S.PROPOSED)
    body = _post(_client(monkeypatch), ("team/api", "2", two), ("team/api", "gone", one), ("team/api", "1", one)).json()
    assert [item["code"] for item in body["results"]] == ["remediation_active", "tag_not_found", None]
    assert body["deleted"] == 1
    assert list(registry.tags["team/api"]) == ["2"]


def test_a_tag_pushed_again_is_refused(monkeypatch, registry):
    registry.tag("team/api", "1", registry.image({"new": 1}))
    body = _post(_client(monkeypatch), ("team/api", "1", OTHER)).json()
    assert body["results"][0]["code"] == "tag_changed"
    assert "1" in registry.tags["team/api"]


@pytest.mark.parametrize(
    ("status", "code"),
    [(400, "registry_delete_unsupported"), (405, "registry_delete_disabled"), (500, "registry_failed")],
)
def test_a_registry_that_wont_delete_changes_nothing(monkeypatch, registry, status, code):
    registry.tag("team/api", "1", registry.image({"a": 1}))
    image_id = _image()
    registry.delete_status = status
    _refused(monkeypatch, registry, code)
    with get_session() as session:
        assert session.get(Image, image_id).active is True


def test_bad_names_never_reach_the_registry(monkeypatch, registry):
    digest = "sha256:" + "1" * 64
    items = [("../x", "1", digest), ("team/api", digest, digest), ("team/api", "a/b", digest)]
    body = _post(_client(monkeypatch), *items).json()
    assert [item["code"] for item in body["results"]] == ["invalid_image_reference"] * 3
    assert registry.requests == []
    assert _post(_client(monkeypatch), ("team/api", "1", "latest")).status_code == 422


@pytest.mark.parametrize("roles", ["dashboard", "operator", "remediator"])
def test_deleting_needs_its_permission(monkeypatch, registry, roles):
    digest = registry.image({"a": 1})
    registry.tag("team/api", "1", digest)
    assert _post(_client(monkeypatch, roles), ("team/api", "1", digest)).status_code == 403
    assert "1" in registry.tags["team/api"]


def test_a_delete_that_cant_be_recorded_says_so(monkeypatch, registry):
    registry.tag("team/api", "1", registry.image({"a": 1}))

    def broken(*args, **kwargs):
        raise RuntimeError("audit is down")

    monkeypatch.setattr("src.api.routes.registry.record_operator_event", broken)
    result = _delete(monkeypatch, registry)
    assert (result["deleted"], result["code"]) == (True, "delete_not_recorded")


# Remediations and scans


@pytest.mark.parametrize("status", list(S))
def test_only_a_finished_remediation_releases_its_image(monkeypatch, registry, status):
    registry.tag("team/api", "1", registry.image({"a": 1}))
    remediation_id = _remediation(f"{HOST}/team/api:1", status)
    if status in (S.COMPLETED, S.FAILED, S.CANCELLED):
        assert _delete(monkeypatch, registry)["deleted"]
    else:
        assert f"Remediation {remediation_id}" in _refused(monkeypatch, registry, "remediation_active")


@pytest.mark.parametrize("status", [S.BUILDING, S.READY, S.PUBLISHED])
@pytest.mark.parametrize("recorded", [True, False])
def test_an_active_remediations_candidate_is_kept(monkeypatch, registry, status, recorded):
    remediation_id = _remediation(f"{HOST}/team/api:1", status)
    tag = f"scrutineering-candidate-{remediation_id}"
    if recorded:
        with get_session() as session:
            session.get(Remediation, remediation_id).candidate_image = f"{HOST}/team/api:{tag}"
    registry.tag("team/api", tag, registry.image({"a": 1}))
    _refused(monkeypatch, registry, "remediation_active", tag)


def test_a_candidate_of_an_image_from_another_registry_is_kept(monkeypatch, registry):
    remediation_id = _remediation("ghcr.io/team/api:1", S.BUILDING)
    tag = f"scrutineering-candidate-{remediation_id}"
    registry.tag("team/api", tag, registry.image({"a": 1}))
    _refused(monkeypatch, registry, "remediation_active", tag)


def test_another_repositorys_candidate_number_doesnt_block(monkeypatch, registry):
    remediation_id = _remediation(f"{HOST}/team/api:1", S.READY)
    tag = f"scrutineering-candidate-{remediation_id}"
    registry.tag("team/web", tag, registry.image({"a": 1}))
    assert _delete(monkeypatch, registry, tag, "team/web")["deleted"]


@pytest.mark.parametrize("status", ["pending", "running"])
@pytest.mark.parametrize("host", [HOST, PUBLIC])
def test_an_image_being_scanned_is_kept(monkeypatch, registry, status, host):
    registry.tag("team/api", "1", registry.image({"a": 1}))
    with get_session() as session:
        create_pending_scan(session, f"{host}/team/api:1").status = status
    _refused(monkeypatch, registry, "scan_active")


# Containers


@pytest.mark.parametrize("host", [HOST, PUBLIC])
def test_a_running_tag_is_kept(monkeypatch, registry, host):
    registry.tag("team/api", "1", registry.image({"a": 1}))
    _container(f"{host}/team/api:1")
    assert "web-1" in _refused(monkeypatch, registry, "running")


def test_a_gone_container_or_one_unseen_for_a_month_doesnt_block(monkeypatch, registry):
    for tag, values in (("1", {"gone": True}), ("2", {"seen_days_ago": 31})):
        registry.tag("team/api", tag, registry.image({tag: 1}))
        _container(f"{HOST}/team/api:{tag}", **values)
        assert _delete(monkeypatch, registry, tag)["deleted"]


def test_docker_hubs_container_of_the_same_name_doesnt_block(monkeypatch, registry):
    digest = registry.image({"a": 1})
    registry.tag("team/api", "1", digest)
    _container("team/api:1", [digest])
    assert _delete(monkeypatch, registry)["deleted"]


@pytest.mark.parametrize("known_by", ["index", "platform", "config"])
def test_the_last_tag_of_a_running_image_is_kept(monkeypatch, registry, known_by):
    import json

    platform = registry.image({"a": 1})
    index = registry.index((platform, "linux/amd64"))
    config = json.loads(registry.content[platform][1])["config"]["digest"]
    registry.tag("team/api", "1", index)
    # It was started under a tag that has since moved, or by digest.
    _container(f"{PUBLIC}/team/api:old", [{"index": index, "platform": platform, "config": config}[known_by]])
    assert "no other tag" in _refused(monkeypatch, registry, "running")

    registry.tag("team/api", "2", index)
    assert _delete(monkeypatch, registry)["deleted"]


def test_a_container_started_by_digest_isnt_taken_for_latest(monkeypatch, registry):
    running = registry.image({"a": 1})
    registry.tag("team/api", "latest", registry.image({"b": 1}))
    _container(f"{HOST}/team/api@{running}", [running])
    assert _delete(monkeypatch, registry, "latest")["deleted"]


def test_an_image_that_cant_be_read_isnt_deleted_while_its_repository_runs(monkeypatch, registry):
    registry.tag("team/api", "1", registry.put({"layers": "x"}, "application/vnd.oci.image.manifest.v1+json"))
    _container(f"{HOST}/team/api:other", [OTHER])
    _refused(monkeypatch, registry, "registry_failed")


def test_without_container_records_last_seen_running_decides(monkeypatch, registry):
    registry.tag("team/api", "1", registry.image({"a": 1}))
    image_id = _image()
    with get_session() as session:
        session.get(Image, image_id).last_seen_running_at = utcnow() - timedelta(minutes=10)
    _refused(monkeypatch, registry, "running")
    with get_session() as session:
        session.get(Image, image_id).last_seen_running_at = utcnow() - timedelta(minutes=31)
    assert _delete(monkeypatch, registry)["deleted"]


def test_with_container_records_a_stopped_container_frees_the_tag_at_once(monkeypatch, registry):
    registry.tag("team/api", "1", registry.image({"a": 1}))
    _container(f"{HOST}/team/api:1", gone=True)
    with get_session() as session:
        session.get(Image, _image()).last_seen_running_at = utcnow()
    assert _delete(monkeypatch, registry)["deleted"]
