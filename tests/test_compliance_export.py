"""Compliance exports (docs/design/reports-compliance.md, step 2)."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import shutil
import subprocess
import zipfile
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from src import signing
from src.api.app import create_app
from src.db.connection import get_session
from src.db.models import ComplianceExport, FindingSource, ScanFinding, Severity
from src.remediation import evidence
from src.reports import export, weekly
from src.scan import sbom as sboms
from tests.test_deployments_api import _completed_remediation, _image

SBOM = '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}'


def _ended_fix() -> tuple[int, datetime]:
    """A completed fix with its evidence bundle, and SBOMs for the scans it cites."""
    image_id = _image()
    rid, _, completed = _completed_remediation(image_id)
    evidence.build_due()
    with get_session() as session:
        bundle = session.query(evidence.EvidenceBundle).one()
        cited = [bundle.before_scan_id, bundle.after_scan_id]
    for scan_id in cited:
        sboms.store(scan_id, image_id, SBOM)
    return rid, completed


def _zip(since: datetime, until: datetime, now: datetime | None = None) -> zipfile.ZipFile:
    data, _ = export.build_zip(since, until, now or until)
    return zipfile.ZipFile(io.BytesIO(data))


def test_the_zip_holds_the_range_and_a_manifest_that_covers_every_file():
    rid, completed = _ended_fix()
    day = completed.replace(hour=0, minute=0, second=0, microsecond=0)
    weekly.build(weekly.ON_DEMAND, day, completed + timedelta(minutes=1), completed + timedelta(minutes=1))
    archive = _zip(day, day + timedelta(days=1))
    names = archive.namelist()
    assert names[:2] == ["manifest.json", "manifest.json.sig"]
    assert any(name.startswith(f"evidence/{rid}-") and name.endswith(".json") for name in names)
    assert sum(name.startswith("sboms/") and name.endswith(".cdx.json") for name in names) == 2
    assert any(name.startswith("reports/on_demand-") for name in names)
    assert {"findings.csv", "audit.json"} <= set(names)

    manifest = json.loads(archive.read("manifest.json"))
    listed = {item["path"]: item for item in manifest["files"]}
    assert set(listed) == set(names) - {"manifest.json", "manifest.json.sig"}
    for path, item in listed.items():
        data = archive.read(path)
        assert (item["sha256"], item["size"]) == (hashlib.sha256(data).hexdigest(), len(data))
    pem = archive.read(f"keys/{manifest['key_id'].removeprefix('sha256:')}.pem").decode()
    assert signing.verify(archive.read("manifest.json"), archive.read("manifest.json.sig").decode().strip(), pem)
    # Each signed file still verifies on its own, with a key from the zip.
    bundle = next(name for name in names if name.startswith("evidence/") and name.endswith(".json"))
    assert signing.verify(archive.read(bundle), archive.read(f"{bundle}.sig").decode().strip(), pem)


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl is not installed")
def test_openssl_verifies_the_manifest(tmp_path):
    _ended_fix()
    archive = _zip(datetime(2020, 1, 1), datetime(2100, 1, 1))
    archive.extractall(tmp_path)
    key = next((tmp_path / "keys").iterdir())
    (tmp_path / "manifest.der").write_bytes(base64.b64decode((tmp_path / "manifest.json.sig").read_text()))
    result = subprocess.run(
        ["openssl", "dgst", "-sha256", "-verify", str(key), "-signature", "manifest.der", "manifest.json"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0 and "Verified OK" in result.stdout


def test_outside_the_range_nothing_but_the_open_findings_is_included():
    _, completed = _ended_fix()
    later = completed + timedelta(days=30)
    names = _zip(later, later + timedelta(days=1)).namelist()
    assert not [name for name in names if name.startswith(("evidence/", "sboms/", "reports/"))]


def test_the_findings_csv_has_open_and_resolved_in_range_and_defuses_formulas():
    image_id = _image()
    now = datetime(2026, 11, 20, 12)
    with get_session() as session:
        for key, resolved, title in (
            ("open", None, '=HYPERLINK("http://evil")'),
            ("fixed-in-range", now - timedelta(hours=1), "fine"),
            ("fixed-before", now - timedelta(days=9), "old"),
        ):
            session.add(
                ScanFinding(
                    image_id=image_id,
                    fingerprint=f"fp-{key}",
                    vuln_key=key,
                    package_name="pkg",
                    severity=Severity.HIGH,
                    source=FindingSource.TRIVY,
                    title=title,
                    resolved_at=resolved,
                )
            )
    rows = list(csv.DictReader(io.StringIO(_zip(now - timedelta(days=1), now).read("findings.csv").decode())))
    assert sorted(row["vuln_key"] for row in rows) == ["fixed-in-range", "open"]
    assert next(row for row in rows if row["vuln_key"] == "open")["title"] == '\'=HYPERLINK("http://evil")'


def test_the_same_records_make_the_same_manifest():
    """Only the signature differs between two builds: ECDSA signatures are randomized."""
    _ended_fix()
    since, until = datetime(2020, 1, 1), datetime(2100, 1, 1)
    first, second = _zip(since, until), _zip(since, until)
    assert first.read("manifest.json") == second.read("manifest.json")
    assert first.namelist() == second.namelist()


def test_an_unusable_key_fails_the_export_instead_of_shipping_it_unsigned(monkeypatch):
    monkeypatch.setattr(signing, "current_key_id", lambda: (_ for _ in ()).throw(PermissionError("read-only")))
    with get_session() as session:
        row = ComplianceExport(
            since=datetime(2026, 1, 1), until=datetime(2026, 2, 1), status="pending", created_at=datetime(2026, 11, 20)
        )
        session.add(row)
        session.flush()
        export_id = row.id
    assert export.build(export_id) == "failed"
    with get_session() as session:
        failed = session.get(ComplianceExport, export_id)
        assert "read-only" in failed.error and failed.data is None


def test_old_exports_are_deleted_and_stuck_ones_fail():
    now = datetime(2026, 11, 20, 12)
    with get_session() as session:
        session.add(ComplianceExport(since=now, until=now, status="ready", created_at=now - timedelta(hours=25)))
        session.add(ComplianceExport(since=now, until=now, status="building", created_at=now - timedelta(hours=2)))
        session.add(ComplianceExport(since=now, until=now, status="pending", created_at=now - timedelta(minutes=5)))
    assert export.prune(now) == 1
    with get_session() as session:
        assert sorted(row.status for row in session.query(ComplianceExport)) == ["failed", "pending"]


def _client(monkeypatch, roles: str) -> TestClient:
    monkeypatch.setenv("PYTHON_API_KEY", "export-key")
    monkeypatch.setenv("DASHBOARD_DEFAULT_ROLES", roles)
    client = TestClient(create_app())
    client.headers["x-api-key"] = "export-key"
    return client


def test_the_api_queues_one_export_at_a_time_for_security_operators(monkeypatch):
    queued = []
    monkeypatch.setattr(export, "queue_build", queued.append)
    body = {"since": "2026-11-01", "until": "2026-11-19"}
    assert (
        _client(monkeypatch, "dashboard,remediator").post("/api/dashboard/compliance/exports", json=body).status_code
        == 403
    )
    client = _client(monkeypatch, "dashboard,security-operator")
    created = client.post("/api/dashboard/compliance/exports", json=body)
    assert created.status_code == 202 and created.json()["status"] == "pending"
    assert created.json()["since"] == "2026-11-01T00:00:00Z" and created.json()["until"] == "2026-11-20T00:00:00Z"
    assert client.post("/api/dashboard/compliance/exports", json=body).status_code == 409
    assert queued == [created.json()["id"]]

    export_id = created.json()["id"]
    assert client.get(f"/api/dashboard/compliance/exports/{export_id}/download").status_code == 404  # not built
    assert export.build(export_id) == "ready"
    download = client.get(f"/api/dashboard/compliance/exports/{export_id}/download")
    assert download.status_code == 200 and download.headers["content-type"] == "application/zip"
    assert download.headers["x-scrutineering-export-sha256"] == hashlib.sha256(download.content).hexdigest()
    assert client.get("/api/dashboard/compliance/exports").json()["items"][0]["status"] == "ready"


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ({"since": "2026-11-19", "until": "2026-11-01"}, "before since"),
        ({"since": "2025-01-01", "until": "2026-11-19"}, "366 days"),
    ],
)
def test_the_range_is_checked(monkeypatch, body, message):
    response = _client(monkeypatch, "security-operator").post("/api/dashboard/compliance/exports", json=body)
    assert response.status_code == 422 and message in response.text
