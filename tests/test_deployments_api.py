"""Deployment routes: containers per image, list counts, and a completed fix's rollout.

docs/design/deployment-observation.md, step 2.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from src.api.app import create_app
from src.db.connection import get_session
from src.db.models import Deployment, FindingObservation, FindingSource, RemediationStatus, ScanFinding
from src.db.repositories import RemediationRepository
from src.scan.records import create_pending_scan, get_or_create_image, scan_identity

S = RemediationStatus
OLD, FIXED, LATER, OTHER = ("sha256:" + letter * 64 for letter in "abcd")
REF = "registry:5000/team/app:1.0"


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _client(monkeypatch, roles: str = "dashboard,remediator") -> TestClient:
    monkeypatch.setenv("PYTHON_API_KEY", "deploy-key")
    monkeypatch.setenv("DASHBOARD_DEFAULT_ROLES", roles)
    client = TestClient(create_app())
    client.headers["x-api-key"] = "deploy-key"
    return client


def _image(reference: str = REF) -> int:
    with get_session() as session:
        return get_or_create_image(session, scan_identity(reference)).id


def _scan(started_at: datetime, digest: str | None, status: str = "completed", findings: list[int] = ()) -> str:
    with get_session() as session:
        scan = create_pending_scan(session, REF)
        scan.status, scan.started_at, scan.image_digest = status, started_at, digest
        for finding_id in findings:
            session.add(FindingObservation(scan_id=scan.scan_id, finding_id=finding_id))
        return scan.scan_id


def _container(image_id: int, name: str, digests: list[str], *, seen: datetime | None = None, gone=None) -> None:
    seen = seen or _now()
    with get_session() as session:
        session.add(
            Deployment(
                container_id=f"id-{name}",
                name=name,
                image_ref=REF,
                image_id=image_id,
                running_digests=digests,
                first_seen_at=seen,
                last_seen_at=seen,
                gone_at=gone,
            )
        )


def test_an_image_lists_its_containers_as_current_stale_or_gone(monkeypatch):
    image_id = _image()
    now = _now()
    _scan(now - timedelta(days=2), OLD)
    _scan(now - timedelta(hours=1), FIXED)
    _scan(now - timedelta(minutes=5), OTHER, status="failed")  # not finished: ignored
    _container(image_id, "web-1", [FIXED])
    _container(image_id, "web-2", [OLD])
    _container(image_id, "silent", [OLD], seen=now - timedelta(hours=2))  # discovery hasn't listed it lately
    _container(image_id, "stopped", [OLD], gone=now - timedelta(hours=3))
    _container(image_id, "long-gone", [OLD], gone=now - timedelta(days=2))

    body = _client(monkeypatch, "dashboard,operator").get(f"/api/dashboard/images/{image_id}/deployments").json()
    assert body["scan_digest"] == FIXED
    assert [(item["name"], item["state"]) for item in body["containers"]] == [("web-1", "current"), ("web-2", "stale")]
    assert [item["name"] for item in body["gone"]] == ["stopped"]
    assert _client(monkeypatch).get("/api/dashboard/images/999999/deployments").status_code == 404


def test_a_tag_only_scan_makes_every_container_unknown(monkeypatch):
    image_id = _image()
    _scan(_now() - timedelta(hours=1), None)
    _container(image_id, "web-1", [OLD])
    body = _client(monkeypatch).get(f"/api/dashboard/images/{image_id}/deployments").json()
    assert [item["state"] for item in body["containers"]] == ["unknown"]


def test_the_images_list_counts_containers_and_stale_ones(monkeypatch):
    image_id = _image()
    _image("registry:5000/team/quiet:1.0")
    _scan(_now() - timedelta(hours=1), FIXED)
    _container(image_id, "web-1", [FIXED])
    _container(image_id, "web-2", [OLD])
    items = {item["name"]: item for item in _client(monkeypatch).get("/api/dashboard/images").json()["items"]}
    assert (items[REF]["containers"], items[REF]["stale_containers"]) == (2, 1)
    assert (
        items["registry:5000/team/quiet:1.0"]["containers"],
        items["registry:5000/team/quiet:1.0"]["stale_containers"],
    ) == (0, 0)


def _finding(image_id: int, remediation_id: int) -> int:
    with get_session() as session:
        finding = ScanFinding(
            image_id=image_id,
            fingerprint="fp-lodash",
            vuln_key="CVE-2021-23337:lodash",
            package_name="lodash",
            source=FindingSource.TRIVY,
            remediation_id=remediation_id,
        )
        session.add(finding)
        session.flush()
        return finding.id


def _completed_remediation(image_id: int) -> tuple[int, int, datetime]:
    with get_session() as session:
        remediation = RemediationRepository.create(session, image_id=image_id, finding_count=1)
        rid, created = remediation.id, remediation.created_at
    finding_id = _finding(image_id, rid)
    _scan(created - timedelta(hours=1), OLD, findings=[finding_id])  # before: the target is there
    _scan(created + timedelta(seconds=1), FIXED)  # the scan that completed it
    completed = created + timedelta(seconds=2)
    for status in (S.APPROVED, S.BUILDING, S.VERIFYING, S.READY):
        with get_session() as session:
            RemediationRepository.update_status(session, rid, status)
    with get_session() as session:
        RemediationRepository.update_status(session, rid, S.COMPLETED, completed_at=completed)
    return rid, finding_id, completed


def test_a_completed_fix_counts_the_containers_that_run_a_fixed_build(monkeypatch):
    image_id = _image()
    rid, finding_id, completed = _completed_remediation(image_id)
    # Later rebuilds: one still clean (also counts as fixed), one where the target came back.
    _scan(completed + timedelta(hours=1), LATER)
    _scan(completed + timedelta(hours=2), OTHER, findings=[finding_id])
    for name, digests in (("web-1", [FIXED]), ("web-2", [LATER]), ("web-3", [OLD]), ("web-4", [OTHER])):
        _container(image_id, name, digests)

    deployment = _client(monkeypatch).get(f"/api/dashboard/remediations/{rid}").json()["deployment"]
    assert deployment == {"containers": 4, "fixed": 2, "not_fixed": ["web-3", "web-4"]}


def test_only_completed_fixes_report_a_deployment(monkeypatch):
    image_id = _image()
    with get_session() as session:
        rid = RemediationRepository.create(session, image_id=image_id, finding_count=1).id
    assert _client(monkeypatch).get(f"/api/dashboard/remediations/{rid}").json()["deployment"] is None


def test_a_fix_scanned_by_tag_reports_containers_but_not_how_many_are_fixed(monkeypatch):
    image_id = _image()
    with get_session() as session:
        remediation = RemediationRepository.create(session, image_id=image_id, finding_count=1)
        rid, created = remediation.id, remediation.created_at
    _scan(created + timedelta(seconds=1), None)
    for status in (S.APPROVED, S.BUILDING, S.VERIFYING, S.READY):
        with get_session() as session:
            RemediationRepository.update_status(session, rid, status)
    with get_session() as session:
        RemediationRepository.update_status(session, rid, S.COMPLETED, completed_at=created + timedelta(seconds=2))
    _container(image_id, "web-1", [OLD])
    deployment = _client(monkeypatch).get(f"/api/dashboard/remediations/{rid}").json()["deployment"]
    assert deployment == {"containers": 1, "fixed": None, "not_fixed": []}
