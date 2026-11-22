"""Previewing and proposing fixes through the API."""

import pytest
from fastapi.testclient import TestClient

from src.api.app import create_app
from src.db.connection import get_session
from src.db.models import FindingSource, RemediationAction, Scan, ScanFinding, Severity
from src.scan.records import queue_scan

API_KEY = "planning-key"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("PYTHON_API_KEY", API_KEY)
    monkeypatch.setenv("DASHBOARD_DEFAULT_ROLES", "dashboard,operator,remediator,security-operator")
    client = TestClient(create_app())
    client.headers["x-api-key"] = API_KEY
    return client


@pytest.fixture
def image():
    scan_id = queue_scan("registry:5000/team/app:1.0", enqueue=lambda *a, **k: None)
    rows = [
        ("lodash", "4.17.20", "node-pkg", "4.17.21", FindingSource.TRIVY, "lodash-key"),
        ("lodash", "4.17.20", "npm", "4.17.21", FindingSource.GRYPE, "lodash-key"),
        ("libssl3", "3.0.7-r0", "alpine", "3.0.19-r0", FindingSource.GRYPE, "ssl-key"),
        ("busybox", "1.35.0-r29", "apk", None, FindingSource.GRYPE, "busybox-key"),
    ]
    with get_session() as session:
        image_id = session.query(Scan).filter_by(scan_id=scan_id).one().image_id
        ids = {}
        for index, (package, version, package_type, fixed, source, vuln_key) in enumerate(rows):
            finding = ScanFinding(
                image_id=image_id,
                fingerprint=f"fp-{index}",
                vuln_key=vuln_key,
                cve_id=f"CVE-2026-{index}",
                package_name=package,
                package_version=version,
                package_type=package_type,
                fixed_version=fixed,
                fix_available=bool(fixed),
                severity=Severity.HIGH,
                source=source,
            )
            session.add(finding)
            session.flush()
            ids[f"{package}-{source.value}"] = finding.id
    return image_id, ids


def _connect(client, image_id):
    response = client.put(f"/api/dashboard/images/{image_id}/source", json={"repository": "team-app"})
    assert response.status_code == 200, response.text


def test_preview_groups_findings_and_needs_a_source_to_be_actionable(client, image):
    image_id, ids = image
    body = {"image_id": image_id, "finding_ids": list(ids.values())}

    unconnected = client.post("/api/dashboard/remediations/preview", json=body).json()
    assert unconnected["source_connected"] is False
    assert unconnected["actionable_count"] == 0
    assert [action["strategy"] for action in unconnected["actions"]] == ["dependency_update", "os_package_upgrade"]

    _connect(client, image_id)
    preview = client.post("/api/dashboard/remediations/preview", json=body).json()
    lodash = preview["actions"][0]
    assert lodash["finding_ids"] == sorted([ids["lodash-trivy"], ids["lodash-grype"]])
    assert lodash["vuln_keys"] == ["lodash-key"]
    assert lodash["safe_to_apply"] is True
    assert preview["actionable_count"] == 3
    assert preview["manual"] == [{"finding_id": ids["busybox-grype"], "reason": "No fixed version is published yet."}]
    assert preview["mutates_state"] is False


def test_proposal_requires_a_connected_source(client, image):
    image_id, ids = image
    response = client.post(
        "/api/dashboard/remediations", json={"image_id": image_id, "finding_ids": [ids["lodash-trivy"]]}
    )
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "source_not_connected"


def test_proposal_refuses_findings_with_no_automatic_fix(client, image):
    image_id, ids = image
    _connect(client, image_id)
    response = client.post(
        "/api/dashboard/remediations",
        json={"image_id": image_id, "finding_ids": [ids["lodash-trivy"], ids["busybox-grype"]]},
    )
    assert response.status_code == 400
    assert response.json()["detail"]["findings"][0]["finding_id"] == ids["busybox-grype"]


def test_proposal_records_one_action_per_fix_and_reserves_the_findings(client, image):
    image_id, ids = image
    _connect(client, image_id)
    selected = [ids["lodash-trivy"], ids["lodash-grype"], ids["libssl3-grype"]]
    created = client.post("/api/dashboard/remediations", json={"image_id": image_id, "finding_ids": selected})
    assert created.status_code == 201, created.text
    remediation = created.json()
    assert remediation["finding_count"] == 3
    assert [action["action_type"] for action in remediation["actions"]] == ["dependency_update", "os_package_upgrade"]
    assert remediation["actions"][0]["after_value"] == "4.17.21"
    assert remediation["actions"][1]["detail"]["packages"] == {"libssl3": "3.0.19-r0"}
    with get_session() as session:
        assert session.query(RemediationAction).count() == 2
        reserved = {f.id for f in session.query(ScanFinding).filter(ScanFinding.remediation_id == remediation["id"])}
    assert reserved == set(selected)

    again = client.post("/api/dashboard/remediations", json={"image_id": image_id, "finding_ids": selected[:1]})
    assert again.status_code == 409


def test_requests_for_unknown_images_or_foreign_findings_are_refused(client, image):
    image_id, ids = image
    preview = client.post("/api/dashboard/remediations/preview", json={"image_id": 999, "finding_ids": [1]})
    assert (preview.status_code, preview.json()["detail"]) == (404, "image_not_found")
    foreign = client.post("/api/dashboard/remediations/preview", json={"image_id": image_id, "finding_ids": [999]})
    assert (foreign.status_code, foreign.json()["detail"]) == (400, "findings_must_belong_to_image")
    unknown = client.post("/api/dashboard/remediations", json={"image_id": 999, "finding_ids": [1]})
    assert (unknown.status_code, unknown.json()["detail"]) == (404, "image_not_found")
    _connect(client, image_id)
    lodash = ids["lodash-trivy"]
    twice = client.post("/api/dashboard/remediations", json={"image_id": image_id, "finding_ids": [lodash, lodash]})
    assert (twice.status_code, twice.json()["detail"]) == (400, "finding_ids_must_be_unique")
    missing = client.post("/api/dashboard/remediations", json={"image_id": image_id, "finding_ids": [lodash, 999]})
    assert (missing.status_code, missing.json()["detail"]) == (400, "findings_must_be_open_and_belong_to_image")


def test_remediations_list_filters_by_status(client, image):
    image_id, ids = image
    _connect(client, image_id)
    created = client.post(
        "/api/dashboard/remediations", json={"image_id": image_id, "finding_ids": [ids["libssl3-grype"]]}
    )
    assert created.status_code == 201, created.text

    assert client.get("/api/dashboard/remediations?status=PROPOSED").json()["total"] == 1
    assert client.get("/api/dashboard/remediations?status=completed").json()["total"] == 0
    invalid = client.get("/api/dashboard/remediations?status=done")
    assert (invalid.status_code, invalid.json()["detail"]) == (400, "invalid_remediation_status")
