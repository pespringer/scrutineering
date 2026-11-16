"""Golden path: the product's core loop, end to end, without live scanners.

This test defines "working" (docs/RESET-PLAN.md, ground rule 1). It drives the
real FastAPI app over HTTP, the real worker functions, and a real schema. The
only stand-ins are the scanner binaries: fake `trivy` and `grype` executables
on PATH replay output recorded from the fixture image
(fixtures/images/vulnerable-node, re-recorded by scripts/record-golden-fixtures.sh).

  scan the fixture -> findings -> propose a fix -> approve -> execute
  -> rescan the patched image -> the targeted finding resolves -> remediation completed

The scan half must pass today. The remediation half is the Phase 4 contract and
is marked xfail(strict=True): when Phase 4 makes it pass, the strict marker
turns that into a failure, so the marker gets removed in the same change.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from src.api.app import create_app
from src.db.connection import get_session
from src.db.models import ScanFinding

RECORDED = Path(__file__).resolve().parents[2] / "fixtures" / "scanner-output" / "vulnerable-node"
IMAGE = "registry:5000/fixtures/vulnerable-node:1.0"
TARGET_CVE, TARGET_PACKAGE = "CVE-2021-23337", "lodash"
API_KEY = "golden-path-key"


@pytest.fixture
def stage(tmp_path, monkeypatch):
    """Fake scanner binaries that replay recorded output for the current stage."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stage_file = tmp_path / "stage"
    for scanner in ("trivy", "grype"):
        script = bin_dir / scanner
        script.write_text(f'#!/bin/sh\ncat "{RECORDED}/$(cat "{stage_file}")-{scanner}.json"\n')
        script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")

    def use(name: str) -> None:
        stage_file.write_text(name)

    use("before")
    return use


@pytest.fixture
def api(monkeypatch):
    """The real app, with scans run synchronously by the real worker."""
    from src.scan import tasks

    monkeypatch.setenv("PYTHON_API_KEY", API_KEY)
    monkeypatch.setenv("DASHBOARD_DEFAULT_ROLES", "dashboard,operator,remediator,security-operator")
    monkeypatch.setenv("REMEDIATION_EXECUTION_ENABLED", "true")
    monkeypatch.setattr(
        tasks,
        "enqueue_scan",
        lambda target, **kw: tasks.run_scan.run.__func__(MagicMock(), target, scan_id=kw["scan_id"]),
    )
    client = TestClient(create_app())
    client.headers["x-api-key"] = API_KEY
    return client


def _scan(api: TestClient, image: str = IMAGE) -> dict:
    response = api.post("/api/dashboard/scans", json={"image_name": image})
    assert response.status_code == 202, response.text
    scan = api.get(f"/api/dashboard/scans/{response.json()['scan_id']}").json()
    assert scan["status"] == "completed", scan
    return scan


def _target_finding(api: TestClient, scan_id: str) -> dict:
    items = api.get(f"/api/dashboard/scans/{scan_id}/findings", params={"limit": 200}).json()["items"]
    page = 0
    while len(items) == 200 * (page + 1):
        page += 1
        items += api.get(
            f"/api/dashboard/scans/{scan_id}/findings", params={"limit": 200, "offset": 200 * page}
        ).json()["items"]
    matches = [item for item in items if item["cve_id"] == TARGET_CVE and item["package_name"] == TARGET_PACKAGE]
    assert len(matches) == 1, f"expected one {TARGET_CVE} finding, got {len(matches)}"
    return matches[0]


def _recorded_count(stage: str) -> int:
    trivy = json.loads((RECORDED / f"{stage}-trivy.json").read_text())
    return sum(len(result.get("Vulnerabilities") or []) for result in trivy["Results"])


def test_scan_half_finds_the_fixture_vulnerabilities(api, stage):
    scan = _scan(api)

    assert scan["image_name"] == IMAGE
    assert scan["findings"] >= _recorded_count("before") * 0.9  # Grype adds some; dedup merges the rest
    lodash = _target_finding(api, scan["scan_id"])
    assert lodash["package_version"] == "4.17.20"
    assert lodash["fixed_version"] == "4.17.21"
    assert lodash["fix_available"] is True
    assert lodash["lifecycle_status"] == "open"
    assert lodash["severity"] == "HIGH"

    image = api.get(f"/api/dashboard/images/{scan['image_id']}").json()["image"]
    assert image["name"] == IMAGE
    assert image["open_findings"] == scan["findings"]
    assert api.get("/api/dashboard/posture/summary").json()["total_findings"] == scan["findings"]


def test_saved_text_fits_its_columns(api, stage):
    """SQLite ignores VARCHAR lengths; Postgres rejects the insert. Check the limits here.

    Regression: Grype has no title field, so long descriptions became titles over
    the 1024-character column and the live scan failed to save.
    """
    import sqlalchemy as sa
    from src.db.models import FindingObservation

    _scan(api)
    with get_session() as session:
        for model in (ScanFinding, FindingObservation):
            for column in model.__table__.columns:
                limit = getattr(column.type, "length", None)
                if isinstance(column.type, sa.String) and limit:
                    longest = session.query(sa.func.max(sa.func.length(column))).scalar() or 0
                    assert longest <= limit, f"{model.__tablename__}.{column.name}: {longest} > {limit}"


def test_rescan_of_the_patched_image_resolves_the_targeted_finding(api, stage):
    """Lifecycle the remediation loop relies on: the fixed image's scan closes the finding."""
    before = _scan(api)
    stage("after")
    after = _scan(api)

    with get_session() as session:
        lodash = session.query(ScanFinding).filter_by(cve_id=TARGET_CVE, package_name=TARGET_PACKAGE).one()
        assert lodash.resolved_at is not None
    # Each scan keeps what it saw.
    assert _target_finding(api, before["scan_id"])["package_version"] == "4.17.20"
    after_items = api.get(f"/api/dashboard/scans/{after['scan_id']}/findings", params={"limit": 200}).json()
    assert TARGET_CVE not in {item["cve_id"] for item in after_items["items"]}


@pytest.mark.xfail(strict=True, reason="Phase 4: remediation of container-image findings is not implemented yet")
def test_remediation_half_fixes_the_dependency_and_verifies_by_rescan(api, stage):
    scan = _scan(api)
    lodash = _target_finding(api, scan["scan_id"])

    preview = api.post(
        "/api/dashboard/remediations/preview", json={"image_id": scan["image_id"], "finding_ids": [lodash["id"]]}
    ).json()
    assert preview["actionable_count"] == 1, preview

    created = api.post(
        "/api/dashboard/remediations", json={"image_id": scan["image_id"], "finding_ids": [lodash["id"]]}
    )
    assert created.status_code == 201, created.text
    remediation_id = created.json()["id"]

    assert api.post(f"/api/dashboard/remediations/{remediation_id}/approve").status_code == 200
    stage("after")  # Phase 4: execution builds the patched image, then rescans it
    assert api.post(f"/api/dashboard/remediations/{remediation_id}/execute").status_code == 202

    remediation = api.get(f"/api/dashboard/remediations/{remediation_id}").json()
    assert remediation["status"] == "completed", remediation
    assert remediation["resolved_finding_count"] == 1
