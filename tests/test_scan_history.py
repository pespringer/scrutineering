"""Scan history, finding lifecycle, and honest scan states, against a real schema."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from src.analytics.dashboard_api import ScanRequest, image_detail, scan_findings
from src.db.connection import get_session
from src.db.models import FindingObservation, Image, Scan, ScanFinding
from src.scan.models import Severity
from src.scan.records import queue_scan
from src.scan.scanners.base import ScannerFinding
from src.scan.tasks import run_scan, schedule_inventory_scans

IMAGE = "registry:5000/team/app:1.0"


def _finding(cve: str, package: str = "openssl", version: str = "1.1.1", fixed: str | None = "1.1.2"):
    return ScannerFinding(
        package_name=package, package_version=version, package_type="os", cve_id=cve,
        title=f"{cve} in {package}", description="", severity=Severity.HIGH, fixed_version=fixed,
    )


def _scan(scan_id: str, *cves: str) -> dict:
    """Run the real worker with Trivy returning `cves` and Grype returning nothing."""
    def scanner(_scanner, _image, source):
        return [(_finding(cve), source) for cve in cves] if source == "trivy" else []

    with patch("src.scan.tasks.run_scanner_sync", side_effect=scanner):
        return run_scan.run.__func__(MagicMock(), IMAGE, scan_id=scan_id)


def _open_cves() -> set[str]:
    with get_session() as session:
        return {f.cve_id for f in session.query(ScanFinding).filter(ScanFinding.resolved_at.is_(None))}


def _scan_cves(scan_id: str) -> set[str]:
    return {item["cve_id"] for item in scan_findings(scan_id, limit=200, offset=0, severity=None,
                                                     fixable_only=False)["items"]}


def test_each_scan_keeps_what_it_saw_across_rescans():
    assert _scan("s1", "CVE-1", "CVE-2")["status"] == "completed"
    assert _scan("s2", "CVE-2", "CVE-3")["status"] == "completed"
    assert _scan("s3", "CVE-1", "CVE-3")["status"] == "completed"

    assert _scan_cves("s1") == {"CVE-1", "CVE-2"}
    assert _scan_cves("s2") == {"CVE-2", "CVE-3"}
    assert _scan_cves("s3") == {"CVE-1", "CVE-3"}
    assert _open_cves() == {"CVE-1", "CVE-3"}

    with get_session() as session:
        findings = {f.cve_id: f for f in session.query(ScanFinding)}
        assert findings["CVE-2"].resolved_at is not None
        assert findings["CVE-1"].reopened_at is not None  # resolved by s2, seen again by s3
        assert session.query(Image).count() == 1
        assert session.query(FindingObservation).count() == 6
        image_id = session.query(Image).one().id
        scan = session.query(Scan).filter_by(scan_id="s3").one()
        assert (scan.total_findings, scan.target) == (2, IMAGE)

    detail = image_detail(image_id, severity=None, limit=100, offset=0)
    assert detail["image"]["open_findings"] == 2
    assert detail["image"]["resolved_findings"] == 1
    assert detail["image"]["name"] == IMAGE


def test_vuln_key_ignores_the_package_version():
    with patch("src.scan.tasks.run_scanner_sync",
               side_effect=lambda _s, _i, source: [(_finding("CVE-9", version="1.0"), source)] if source == "trivy" else []):
        run_scan.run.__func__(MagicMock(), IMAGE, scan_id="v1")
    with patch("src.scan.tasks.run_scanner_sync",
               side_effect=lambda _s, _i, source: [(_finding("CVE-9", version="1.1"), source)] if source == "trivy" else []):
        run_scan.run.__func__(MagicMock(), IMAGE, scan_id="v2")
    with get_session() as session:
        rows = session.query(ScanFinding).all()
        assert len({row.fingerprint for row in rows}) == 2
        assert len({row.vuln_key for row in rows}) == 1


def test_unexpected_worker_error_leaves_the_scan_failed_not_pending():
    with patch("src.scan.tasks.run_scanners_concurrently", side_effect=RuntimeError("boom")):
        result = run_scan.run.__func__(MagicMock(), IMAGE, scan_id="crash")
    assert result["status"] == "failed"
    with get_session() as session:
        scan = session.query(Scan).filter_by(scan_id="crash").one()
        assert scan.status == "failed"
        assert "boom" in scan.error_message
        assert scan.completed_at is not None


def test_queue_failure_marks_the_scan_failed():
    def broken_queue(*_args, **_kwargs):
        raise ConnectionError("redis down")

    with pytest.raises(ConnectionError):
        queue_scan(IMAGE, scan_id="q1", enqueue=broken_queue)
    with get_session() as session:
        scan = session.query(Scan).filter_by(scan_id="q1").one()
        assert (scan.status, scan.phase) == ("failed", "queue_failed")


def test_queued_scan_is_pending_and_bound_to_its_image_before_the_worker_runs():
    calls = []
    scan_id = queue_scan(IMAGE, priority="high", enqueue=lambda *a, **k: calls.append((a, k)))
    assert calls == [((IMAGE,), {"priority": "high", "scan_id": scan_id})]
    with get_session() as session:
        scan = session.query(Scan).filter_by(scan_id=scan_id).one()
        assert (scan.status, scan.target, scan.scheduler_type) == ("pending", IMAGE, "manual")
        assert scan.image.full_name == IMAGE


def test_scheduled_scans_create_pending_records(monkeypatch):
    with get_session() as session:
        session.add(Image(registry_name="other", repo_name="registry:5000/team/app", tag="1.0"))
    queued = []
    monkeypatch.setenv("SCAN_COOLDOWN_SECONDS", "0")
    monkeypatch.setattr("src.scan.tasks.enqueue_scan", lambda target, **kw: queued.append((target, kw)))

    assert schedule_inventory_scans.run()["queued"] == 1
    assert queued[0][0] == IMAGE
    with get_session() as session:
        scan = session.query(Scan).one()
        assert (scan.status, scan.scheduler_type, scan.scan_id) == ("pending", "scheduled", queued[0][1]["scan_id"])


@pytest.mark.parametrize("value", ["fs:/etc", "fs:/workspace/repository"])
def test_public_scan_form_rejects_filesystem_targets(value):
    with pytest.raises(ValidationError):
        ScanRequest(image_name=value)


def test_public_scan_form_accepts_image_references():
    assert ScanRequest(image_name=" registry:5000/team/app:1.0 ").image_name == IMAGE


def test_scan_request_rejects_malformed_digests():
    with pytest.raises(ValidationError):
        ScanRequest(image_name="nginx@sha256:short")


def test_cancelled_scan_is_not_overwritten_by_the_worker():
    queue_scan(IMAGE, scan_id="c1", enqueue=lambda *a, **k: None)
    with get_session() as session:
        session.query(Scan).filter_by(scan_id="c1").one().status = "cancelled"
    result = _scan("c1", "CVE-1")
    assert result["status"] == "cancelled"
    with get_session() as session:
        assert session.query(Scan).filter_by(scan_id="c1").one().status == "cancelled"
        assert session.query(FindingObservation).count() == 0


def test_observation_payload_reports_what_that_scan_saw():
    _scan("o1", "CVE-1")
    item = scan_findings("o1", limit=10, offset=0, severity=None, fixable_only=True)["items"][0]
    assert item["fixed_version"] == "1.1.2"
    assert item["fix_available"] is True
    assert "remediated" not in item
    assert item["observed_at"]


def test_partial_scan_records_observations_without_resolving_missing_findings():
    _scan("p1", "CVE-1", "CVE-2")

    def trivy_only(_scanner, _image, source):
        if source == "grype":
            from src.scan.scanners.base import ScannerError
            raise ScannerError("grype", "down", "")
        return [(_finding("CVE-1"), source)]

    with patch("src.scan.tasks.run_scanner_sync", side_effect=trivy_only):
        result = run_scan.run.__func__(MagicMock(), IMAGE, scan_id="p2")
    assert result["status"] == "partial"
    assert _open_cves() == {"CVE-1", "CVE-2"}
    assert _scan_cves("p2") == {"CVE-1"}


def test_retry_uses_the_original_target(monkeypatch):
    from src.analytics.dashboard_api import BulkIdsRequest, bulk_retry_scans

    queue_scan("registry:5000/team/app:2.0", scan_id="r1", enqueue=lambda *a, **k: None)
    with get_session() as session:
        session.query(Scan).filter_by(scan_id="r1").one().status = "failed"
    queued = []
    monkeypatch.setattr("src.scan.tasks.enqueue_scan", lambda target, **kw: queued.append(target))
    request = SimpleNamespace(state=SimpleNamespace(principal_roles=["operator"], principal_id="op", auth_method="api_key"))

    result = bulk_retry_scans(BulkIdsRequest(ids=["r1"]), request)

    assert result["count"] == 1
    assert queued == ["registry:5000/team/app:2.0"]
