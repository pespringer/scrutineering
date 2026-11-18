"""CycloneDX SBOMs for scans (docs/design/sbom-evidence.md): generation, storage, pruning, downloads."""

from __future__ import annotations

import asyncio
import hashlib
import json
import stat
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api.app import create_app
from src.db.connection import get_session
from src.db.models import Sbom
from src.scan import sbom as sboms
from src.scan.records import create_pending_scan
from src.scan.scanners.base import ScannerError
from src.scan.scanners.trivy import TrivyScanner

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "scanner-output" / "vulnerable-node" / "cyclonedx.json"
NESTED = json.dumps(
    {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [{"name": "a", "components": [{"name": "a1"}, {"name": "a2"}]}, {"name": "b"}],
    }
)


def _scan(image: str = "registry:5000/team/app:1.0") -> tuple[str, int]:
    with get_session() as session:
        scan = create_pending_scan(session, image)
        return scan.scan_id, scan.image_id


def _fake_trivy(tmp_path, body: str) -> str:
    path = tmp_path / "trivy"
    path.write_text(f'#!/bin/sh\necho "$@" > {tmp_path}/args\n{body}\n')
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return str(path)


def test_trivy_writes_cyclonedx_from_its_cache_with_the_scan_s_transport(tmp_path):
    trivy = _fake_trivy(tmp_path, f"cat {FIXTURE}")
    scanner = TrivyScanner(trivy_cmd=trivy, cache_dir="/cache", insecure=True)
    document = asyncio.run(scanner.sbom("registry:5000/team/app@sha256:" + "a" * 64))
    assert json.loads(document)["bomFormat"] == "CycloneDX"
    args = (tmp_path / "args").read_text().split()
    assert args == [
        "image",
        "--insecure",
        "--format",
        "cyclonedx",
        "--cache-dir",
        "/cache",
        "registry:5000/team/app@sha256:" + "a" * 64,
    ]


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("echo boom >&2; exit 2", "SBOM exit code 2"),
        ("echo not json", "not JSON"),
        ('echo \'{"bomFormat": "SPDX"}\'', "not a CycloneDX document"),
    ],
)
def test_trivy_sbom_failures_are_scanner_errors(tmp_path, body, message):
    with pytest.raises(ScannerError, match=message):
        asyncio.run(TrivyScanner(trivy_cmd=_fake_trivy(tmp_path, body)).sbom("alpine:3.20"))


def test_an_sbom_is_stored_exactly_with_its_hash_and_nested_component_count():
    scan_id, image_id = _scan()
    stored = sboms.store(scan_id, image_id, NESTED)
    assert (stored.components, stored.spec_version, stored.format) == (4, "1.6", "cyclonedx-json")
    with get_session() as session:
        row = session.query(Sbom).one()
        assert row.document == NESTED
        assert row.sha256 == hashlib.sha256(NESTED.encode()).hexdigest()


def test_a_failed_sbom_is_reported_not_raised():
    class Broken:
        async def sbom(self, target):
            raise ScannerError("trivy", "SBOM timed out after 600s", "")

    scan_id, image_id = _scan()
    assert sboms.generate(scan_id, image_id, "alpine:3.20", Broken()) == "failed"

    class Works:
        async def sbom(self, target):
            return NESTED

    assert sboms.generate(scan_id, image_id, "alpine:3.20", Works()) == "stored"
    with get_session() as session:
        assert session.query(Sbom).count() == 1


def test_pruning_keeps_each_image_s_newest_sbom():
    app_scans = [_scan("registry:5000/team/app:1.0") for _ in range(3)]
    other = _scan("registry:5000/team/other:1.0")
    for scan_id, image_id in [*app_scans, other]:
        sboms.store(scan_id, image_id, NESTED)
    assert sboms.prune() == 2
    with get_session() as session:
        kept = {row.scan_id for row in session.query(Sbom)}
    assert kept == {app_scans[-1][0], other[0]}
    assert sboms.prune() == 0


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("PYTHON_API_KEY", "sbom-key")
    client = TestClient(create_app())
    client.headers["x-api-key"] = "sbom-key"
    return client


def test_downloads_and_the_image_summary(client):
    first, image_id = _scan()
    sboms.store(first, image_id, NESTED)
    latest, _ = _scan()
    document = FIXTURE.read_text()
    sboms.store(latest, image_id, document)

    by_scan = client.get(f"/api/dashboard/scans/{first}/sbom")
    assert by_scan.status_code == 200 and by_scan.text == NESTED
    assert by_scan.headers["content-type"].startswith("application/vnd.cyclonedx+json")
    assert by_scan.headers["content-disposition"] == 'attachment; filename="registry_5000_team_app_1.0.cdx.json"'
    by_image = client.get(f"/api/dashboard/images/{image_id}/sbom")
    assert by_image.text == document and by_image.headers["x-scrutineering-scan-id"] == latest
    summary = client.get(f"/api/dashboard/images/{image_id}").json()["image"]["sbom"]
    assert summary["scan_id"] == latest and summary["components"] == len(json.loads(document)["components"])
    assert summary["sha256"] == hashlib.sha256(document.encode()).hexdigest()


def test_missing_sboms_are_404(client):
    _, image_id = _scan()
    assert client.get("/api/dashboard/scans/nope/sbom").status_code == 404
    assert client.get(f"/api/dashboard/images/{image_id}/sbom").status_code == 404
    assert client.get("/api/dashboard/images/99999/sbom").status_code == 404
    assert client.get(f"/api/dashboard/images/{image_id}").json()["image"]["sbom"] is None
