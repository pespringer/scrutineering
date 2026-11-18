"""Signed evidence bundles (docs/design/sbom-evidence.md): when they're due, what they hold, who reads them."""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

from src import signing
from src.api.app import create_app
from src.db.connection import get_session
from src.db.models import EvidenceBundle, Image, RemediationActionType, RemediationStatus, Sbom
from src.db.repositories import RemediationRepository
from src.remediation import evidence
from src.scan import sbom as sboms
from src.scan.records import create_pending_scan

S = RemediationStatus
SBOM = '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}'


def _remediation() -> int:
    with get_session() as session:
        image = Image(repo_name="registry:5000/team/app", tag="1.0")
        session.add(image)
        session.flush()
        remediation = RemediationRepository.create(session, image_id=image.id, finding_count=1)
        RemediationRepository.add_action(
            session, remediation.id, RemediationActionType.DEPENDENCY_UPDATE, before_value="1.0", after_value="1.1"
        )
        return remediation.id


def _advance(remediation_id: int, *statuses: S, **values) -> None:
    for status in statuses:
        with get_session() as session:
            RemediationRepository.update_status(session, remediation_id, status, **values)


def _bundles(remediation_id: int) -> list[EvidenceBundle]:
    with get_session() as session:
        return session.query(EvidenceBundle).filter_by(remediation_id=remediation_id).order_by(EvidenceBundle.id).all()


def test_a_bundle_is_due_once_per_ending():
    rid = _remediation()
    assert evidence.build_due() == 0  # still proposed
    _advance(rid, S.APPROVED, S.BUILDING, S.FAILED, error_message="the patched image still has 1 target")
    assert evidence.build_due() == 1
    assert evidence.build_due() == 0  # frozen: never rebuilt

    _advance(rid, S.PROPOSED)  # retry
    assert evidence.build_due() == 0
    _advance(rid, S.APPROVED, S.BUILDING, S.FAILED, error_message="still failing")
    assert evidence.build_due() == 1
    first, second = _bundles(rid)
    assert json.loads(first.document)["remediation"]["error"] == "the patched image still has 1 target"
    assert json.loads(second.document)["remediation"]["error"] == "still failing"


def test_cancelled_remediations_get_no_bundle():
    rid = _remediation()
    _advance(rid, S.CANCELLED)
    assert evidence.build_due() == 0 and _bundles(rid) == []


def test_the_stored_bytes_are_canonical_and_signed():
    rid = _remediation()
    _advance(rid, S.APPROVED, S.BUILDING, S.FAILED, error_message="x")
    [bundle] = [evidence.build(rid)]
    document = json.loads(bundle.document)
    assert bundle.document.encode() == evidence.canonical(document)
    assert document["plan"] == [{"strategy": "dependency_update", "from": "1.0", "to": "1.1", "detail": {}}]
    assert document["remediation"]["image"] == "registry:5000/team/app:1.0"
    with get_session() as session:
        from src.db.models import SigningKey

        pem = session.query(SigningKey).one().public_key_pem
    assert signing.verify(bundle.document.encode(), bundle.signature, pem)


def test_an_unusable_key_leaves_the_bundle_unsigned(monkeypatch):
    monkeypatch.setattr(signing, "sign", lambda data: (_ for _ in ()).throw(PermissionError("read-only")))
    rid = _remediation()
    _advance(rid, S.APPROVED, S.BUILDING, S.FAILED, error_message="x")
    bundle = evidence.build(rid)
    assert bundle.signature is None and bundle.key_id is None


def test_sboms_cited_by_a_bundle_survive_pruning():
    rid = _remediation()
    with get_session() as session:
        image_id = session.query(Image.id).scalar()
        old = create_pending_scan(session, "registry:5000/team/app:1.0")
        old.status = "completed"
        old_id = old.scan_id
    sboms.store(old_id, image_id, SBOM)
    with get_session() as session:
        session.add(
            EvidenceBundle(
                remediation_id=rid,
                outcome="completed",
                ended_at=old.started_at,
                before_scan_id=old_id,
                document="{}",
                sha256="0",
            )
        )
    with get_session() as session:
        newer = create_pending_scan(session, "registry:5000/team/app:1.0").scan_id
    sboms.store(newer, image_id, SBOM)
    assert sboms.prune() == 0  # the old SBOM is cited, the new one is the latest
    with get_session() as session:
        assert {row.scan_id for row in session.query(Sbom)} == {old_id, newer}


def _client(monkeypatch, roles: str) -> TestClient:
    monkeypatch.setenv("PYTHON_API_KEY", "evidence-key")
    monkeypatch.setenv("DASHBOARD_DEFAULT_ROLES", roles)
    client = TestClient(create_app())
    client.headers["x-api-key"] = "evidence-key"
    return client


def test_the_bundle_needs_the_remediator_role_and_exists_only_once_built(monkeypatch):
    rid = _remediation()
    remediator = _client(monkeypatch, "dashboard,remediator")
    assert remediator.get(f"/api/dashboard/remediations/{rid}/evidence").status_code == 404
    assert remediator.get(f"/api/dashboard/remediations/{rid}").json()["evidence"] is None
    _advance(rid, S.APPROVED, S.BUILDING, S.FAILED, error_message="x")
    evidence.build_due()

    download = remediator.get(f"/api/dashboard/remediations/{rid}/evidence")
    assert download.status_code == 200 and download.headers["content-type"].startswith("application/json")
    signature = remediator.get(f"/api/dashboard/remediations/{rid}/evidence.sig").text.strip()
    assert signature == download.headers["x-scrutineering-signature"]
    summary = remediator.get(f"/api/dashboard/remediations/{rid}").json()["evidence"]
    assert summary["outcome"] == "failed" and summary["signed"] is True

    viewer = _client(monkeypatch, "dashboard,operator")
    assert viewer.get(f"/api/dashboard/remediations/{rid}/evidence").status_code == 403
    assert viewer.get(f"/api/dashboard/remediations/{rid}/evidence.sig").status_code == 403


def test_build_refuses_remediations_that_have_not_ended():
    rid = _remediation()
    assert evidence.build(rid) is None
    assert evidence.build(999999) is None
