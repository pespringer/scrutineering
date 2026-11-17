"""Remediation execution: patch, build, verify, and every way it can stop."""

import json
import os
import stat
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

from src.api.app import create_app
from src.db.connection import get_session
from src.db.models import Remediation, RemediationStatus, Scan, ScanFinding
from src.db.repositories import RemediationRepository
from src.remediation import worker
from src.scan.inspection import InspectionResult
from src.scan.records import queue_scan
from src.scan.utils.db import persist_findings

API_KEY = "worker-key"
LODASH = {"cve_id": "CVE-2021-23337", "package_name": "lodash", "package_version": "4.17.20", "severity": "high"}
EXISTING = {"cve_id": "CVE-2023-0001", "package_name": "libssl3", "package_version": "3.0.7-r0", "severity": "high"}


@pytest.fixture
def tools(tmp_path, monkeypatch):
    """Fake npm (edits package.json) and buildctl (exit code from BUILD_EXIT)."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    scripts = {
        "npm": "import json\nm=json.load(open('package.json'))\nm['dependencies']['lodash']='4.17.21'\n"
        "json.dump(m, open('package.json','w'))\n",
        "buildctl": "import json, os, sys\na=sys.argv\n"
        "if 'target=scrutineering-test' in a:\n"
        "    d=[x.split('=',1)[1] for x in a if x.startswith('dockerfile=')][0]\n"
        "    open(os.environ['TEST_LOG'],'w').write(open(os.path.join(d,'Dockerfile')).read())\n"
        "    if os.environ.get('TEST_EXIT'):\n"
        "        sys.stderr.write('#9 RUN npm test\\n1 failing: lodash.template'); sys.exit(1)\n"
        "    sys.exit(0)\n"
        "if os.environ.get('BUILD_EXIT'):\n"
        "    sys.stderr.write('step 3/5 failed: npm ci'); sys.exit(1)\n"
        "out=open(a[a.index('--metadata-file')+1],'w')\n"
        "json.dump({'containerimage.digest': 'sha256:'+'d'*64}, out)\n",
    }
    for name, body in scripts.items():
        path = bin_dir / name
        path.write_text(f"#!{sys.executable}\n{body}")
        path.chmod(path.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("TEST_LOG", str(tmp_path / "test-dockerfile"))
    monkeypatch.delenv("BUILD_EXIT", raising=False)
    monkeypatch.delenv("TEST_EXIT", raising=False)


@pytest.fixture
def remediation_id(tmp_path, monkeypatch, tools):
    sources = tmp_path / "sources"
    repo = sources / "app"
    repo.mkdir(parents=True)
    (repo / "Dockerfile").write_text("FROM node:18.12-alpine\nCOPY . .\n")
    (repo / "package.json").write_text(json.dumps({"dependencies": {"lodash": "4.17.20"}}))
    for args in (["init", "-q"], ["add", "."], ["commit", "-q", "-m", "init"]):
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *args], cwd=repo, check=True)
    monkeypatch.setenv("REMEDIATION_SOURCES_ROOT", str(sources))
    monkeypatch.setenv("PYTHON_API_KEY", API_KEY)
    monkeypatch.setenv("DASHBOARD_DEFAULT_ROLES", "dashboard,remediator,security-operator")

    scan_id = queue_scan("registry:5000/team/app:1.0", enqueue=lambda *a, **k: None)
    with get_session() as session:
        image_id = session.query(Scan).filter_by(scan_id=scan_id).one().image_id
    lodash = {**LODASH, "package_type": "npm", "fixed_version": "4.17.21"}
    persist_findings(scan_id, image_id, [lodash, EXISTING], "trivy", reconcile_missing=True)
    client = TestClient(create_app())
    client.headers["x-api-key"] = API_KEY
    client.put(f"/api/dashboard/images/{image_id}/source", json={"repository": "app"})
    with get_session() as session:
        finding_id = session.query(ScanFinding).filter_by(package_name="lodash").one().id
    created = client.post("/api/dashboard/remediations", json={"image_id": image_id, "finding_ids": [finding_id]})
    rid = created.json()["id"]
    with get_session() as session:
        for status in (RemediationStatus.APPROVED, RemediationStatus.BUILDING):
            RemediationRepository.update_status(session, rid, status)
    return rid


def _candidate_scan(monkeypatch, *findings, complete=True):
    scanned = []

    def fake(reference):
        scanned.append(reference)
        return InspectionResult(complete=complete, scanned_reference=reference, findings=list(findings), errors=[])

    monkeypatch.setattr(worker, "inspect_image", fake)
    return scanned


def _record(rid) -> Remediation:
    with get_session() as session:
        record = session.get(Remediation, rid)
        session.expunge(record)
        return record


def test_a_clean_candidate_is_ready_with_its_patch_and_digest(remediation_id, monkeypatch):
    scanned = _candidate_scan(monkeypatch, EXISTING)
    result = worker.run_remediation(remediation_id)

    assert result["status"] == "ready"
    record = _record(remediation_id)
    assert record.status == RemediationStatus.READY and record.verified
    assert '"lodash": "4.17.21"' in record.patch and len(record.source_commit) == 40
    assert record.candidate_image == f"registry:5000/team/app:scrutineering-candidate-{remediation_id}"
    assert scanned == ["registry:5000/team/app@sha256:" + "d" * 64]  # the exact image that was built
    assert record.verification["still_present"] == [] and record.verification["new_critical_or_high"] == []
    with get_session() as session:
        events = [event.event_type for event in RemediationRepository.list_events(session, remediation_id)]
    assert events[-3:] == ["patched", "built", "verified"]


def test_new_critical_findings_need_acceptance(remediation_id, monkeypatch):
    new = {"cve_id": "CVE-2026-9999", "package_name": "musl", "package_version": "1.2", "severity": "critical"}
    _candidate_scan(monkeypatch, EXISTING, new, {**new, "cve_id": "CVE-2026-1", "severity": "medium"})
    assert worker.run_remediation(remediation_id)["status"] == "needs_acceptance"
    verification = _record(remediation_id).verification
    assert [item["cve_id"] for item in verification["new_critical_or_high"]] == ["CVE-2026-9999"]


def test_a_candidate_that_still_has_the_target_fails(remediation_id, monkeypatch):
    _candidate_scan(monkeypatch, {**LODASH, "package_version": "4.17.21"})
    assert worker.run_remediation(remediation_id)["status"] == "failed"
    record = _record(remediation_id)
    assert record.status == RemediationStatus.FAILED
    assert "still has 1 of the targeted findings" in record.error_message


def test_an_incomplete_candidate_scan_fails(remediation_id, monkeypatch):
    _candidate_scan(monkeypatch, complete=False)
    worker.run_remediation(remediation_id)
    assert "did not complete" in _record(remediation_id).error_message


def test_a_build_failure_records_the_build_output(remediation_id, monkeypatch):
    monkeypatch.setenv("BUILD_EXIT", "1")
    _candidate_scan(monkeypatch)
    worker.run_remediation(remediation_id)
    record = _record(remediation_id)
    assert record.status == RemediationStatus.FAILED
    assert "the build failed" in record.error_message and "npm ci" in record.error_message
    assert record.patch  # the patch is kept for diagnosis


def test_a_missing_repository_fails_without_building(remediation_id, monkeypatch, tmp_path):
    monkeypatch.setenv("REMEDIATION_SOURCES_ROOT", str(tmp_path / "elsewhere"))
    _candidate_scan(monkeypatch)
    worker.run_remediation(remediation_id)
    assert "not a git repository" in _record(remediation_id).error_message


def test_cancelling_during_the_build_stops_the_run_and_keeps_cancelled(remediation_id, monkeypatch):
    def cancel_during_build(source, build_args, reference):
        with get_session() as session:
            RemediationRepository.update_status(session, remediation_id, RemediationStatus.CANCELLED)
        return worker.BuiltImage(reference=reference, digest="sha256:" + "e" * 64)

    monkeypatch.setattr(worker, "build_and_push", cancel_during_build)
    scanned = _candidate_scan(monkeypatch)
    result = worker.run_remediation(remediation_id)

    assert result["reason"] == "not_running"
    assert _record(remediation_id).status == RemediationStatus.CANCELLED
    assert scanned == []  # the candidate is never scanned


def test_only_building_remediations_run(remediation_id):
    with get_session() as session:
        RemediationRepository.update_status(session, remediation_id, RemediationStatus.CANCELLED)
    assert worker.run_remediation(remediation_id) == {
        "remediation_id": remediation_id,
        "status": "cancelled",
        "reason": "not_running",
    }


def _set_test_command(remediation_id, command):
    from src.db.models import ImageSource

    with get_session() as session:
        image_id = session.get(Remediation, remediation_id).image_id
        session.query(ImageSource).filter_by(image_id=image_id).one().test_command = command


def test_the_test_command_runs_in_the_candidate_before_it_is_scanned(remediation_id, monkeypatch, tmp_path):
    _set_test_command(remediation_id, ["npm", "test"])
    scanned = _candidate_scan(monkeypatch, EXISTING)

    assert worker.run_remediation(remediation_id)["status"] == "ready"
    dockerfile = (tmp_path / "test-dockerfile").read_text()
    assert "FROM node:18.12-alpine AS scrutineering-candidate" in dockerfile
    assert dockerfile.rstrip().endswith('FROM scrutineering-candidate AS scrutineering-test\nRUN ["npm", "test"]')
    assert len(scanned) == 1
    with get_session() as session:
        events = [event.event_type for event in RemediationRepository.list_events(session, remediation_id)]
    assert events[-4:] == ["patched", "built", "tested", "verified"]


def test_failing_tests_fail_the_remediation_with_their_output(remediation_id, monkeypatch):
    _set_test_command(remediation_id, ["npm", "test"])
    monkeypatch.setenv("TEST_EXIT", "1")
    scanned = _candidate_scan(monkeypatch, EXISTING)

    assert worker.run_remediation(remediation_id)["status"] == "failed"
    record = _record(remediation_id)
    assert record.status == RemediationStatus.FAILED
    assert "the candidate's tests failed (npm test)" in record.error_message
    assert "1 failing: lodash.template" in record.error_message
    assert record.candidate_digest  # the candidate was built; it is the tests that failed
    assert scanned == []  # a candidate that fails its tests is not scanned
