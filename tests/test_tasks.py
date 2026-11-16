"""Tests for the Celery scan orchestrator tasks."""

import uuid
import threading
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.scan.scanners.base import ScannerError, ScannerFinding
from src.scan.models import Severity
from src.scan.utils.db import _finding_source, apply_finding_observation


def _make_finding(cve=None, pkg="openssl", version="1.1.1", severity=Severity.HIGH, title=None):
    """Helper to create ScannerFinding instances for tests."""
    return ScannerFinding(
        package_name=pkg,
        package_version=version,
        package_type="os",
        cve_id=cve,
        title=title or f"Test vuln {cve or 'unknown'}",
        description="Test vulnerability",
        severity=severity,
        fixed_version="1.1.2",
    )


# ---------------------------------------------------------------------------
# Tests for run_scan task
# ---------------------------------------------------------------------------


class TestRunScan:
    """Tests for the run_scan Celery task."""

    def test_merged_findings_keep_a_valid_single_source_enum(self):
        assert _finding_source({"sources": ["trivy", "grype"]}, "trivy,grype").value == "grype"

    @patch("src.scan.tasks.run_scanner_sync")
    @patch("src.scan.tasks.persist_findings")
    def test_both_scanners_succeed(self, mock_persist, mock_scan, tmp_path):
        """Both scanners return findings, all get deduped and persisted."""
        from src.scan.tasks import run_scan

        # Setup mock findings
        finding1 = _make_finding(cve="CVE-2024-0001", pkg="openssl")
        finding2 = _make_finding(cve="CVE-2024-0002", pkg="curl")
        finding3 = _make_finding(cve="CVE-2024-0001", pkg="openssl")  # duplicate

        def scan_side_effect(scanner, image_name, source_name):
            if source_name == "trivy":
                return [(finding1, "trivy"), (finding2, "trivy")]
            elif source_name == "grype":
                return [(finding3, "grype")]
            return []

        mock_scan.side_effect = scan_side_effect
        mock_persist.return_value = 2

        mock_self = MagicMock()
        result = run_scan.run.__func__(mock_self, "nginx:1.25", scan_id="test-001")

        assert result["status"] == "completed"
        assert result["scan_id"] == "test-001"
        assert result["findings"] == 2  # CVE-0001 deduped, CVE-0002 unique
        assert result["scanners_completed"] == ["trivy", "grype"]
        assert result["scanners_failed"] == []
        assert result["persisted"] == 2
        assert result["errors"] == []
        assert result["findings_by_source"]["trivy"] == 2
        assert result["findings_by_source"]["grype"] == 1

    @patch("src.scan.tasks.run_scanner_sync")
    def test_trivy_fails_grype_succeeds(self, mock_scan):
        """Trivy fails but Grype results are saved (partial success)."""
        from src.scan.tasks import run_scan

        def scan_side_effect(scanner, image_name, source_name):
            if source_name == "trivy":
                raise ScannerError("trivy", "command not found", "output")
            return []

        mock_scan.side_effect = scan_side_effect

        mock_self = MagicMock()
        result = run_scan.run.__func__(mock_self, "nginx:1.25", scan_id="test-002")

        assert result["status"] == "partial"
        assert "trivy" in result["scanners_failed"]
        assert "grype" in result["scanners_completed"]
        assert len(result["errors"]) == 1
        assert result["errors"][0]["scanner"] == "trivy"

    @patch("src.scan.tasks.run_scanner_sync")
    def test_both_scanners_fail(self, mock_scan):
        """Both scanners fail — task should return failed status."""
        from src.scan.tasks import run_scan

        mock_scan.side_effect = ScannerError("scanner", "failed", "err")

        mock_self = MagicMock()
        result = run_scan.run.__func__(mock_self, "bad-image:latest", scan_id="test-003")

        assert result["status"] == "failed"
        assert result["scanners_completed"] == []
        assert len(result["scanners_failed"]) == 2
        assert len(result["errors"]) == 2
        assert mock_self.update_state.call_args.kwargs["state"] == "SCAN_FAILED"

    @patch("src.scan.tasks.run_scanner_sync")
    @patch("src.scan.tasks.persist_findings")
    def test_no_findings_found(self, mock_persist, mock_scan):
        """Scanners run but find no vulnerabilities."""
        from src.scan.tasks import run_scan

        mock_scan.return_value = []
        mock_persist.return_value = 0

        mock_self = MagicMock()
        result = run_scan.run.__func__(mock_self, "clean-image:latest", scan_id="test-004")

        assert result["status"] == "completed"
        assert result["findings"] == 0
        assert result["persisted"] == 0

    @patch("src.scan.tasks.run_scanner_sync")
    @patch("src.scan.tasks.persist_findings")
    def test_database_persist_fails_marks_the_scan_failed(self, mock_persist, mock_scan):
        """Scanners succeed but saving findings fails: the scan must not claim completion."""
        from src.db.connection import get_session
        from src.db.models import Scan
        from src.scan.tasks import run_scan

        mock_scan.return_value = [(_make_finding(cve="CVE-2024-0001"), "trivy")]
        mock_persist.side_effect = Exception("DB connection refused")

        result = run_scan.run.__func__(MagicMock(), "nginx:1.25", scan_id="test-005")

        assert result["status"] == "failed"
        assert result["errors"][-1] == {"component": "database", "error": "DB connection refused"}
        with get_session() as session:
            scan = session.query(Scan).filter_by(scan_id="test-005").one()
            assert (scan.status, scan.phase) == ("failed", "persistence_failed")
            assert "could not save findings" in scan.error_message

    @patch("src.scan.tasks.run_scanner_sync")
    @patch("src.scan.tasks.persist_findings")
    def test_single_scanner_mode(self, mock_persist, mock_scan):
        """Run with only trivy scanner specified."""
        from src.scan.tasks import run_scan

        finding = _make_finding(cve="CVE-2024-0001")
        mock_scan.return_value = [(finding, "trivy")]
        mock_persist.return_value = 1

        mock_self = MagicMock()
        result = run_scan.run.__func__(mock_self, "nginx:1.25", scanners=["trivy"])

        assert result["status"] == "completed"
        assert result["scanners_completed"] == ["trivy"]
        assert "grype" not in result["scanners_completed"]

    @patch("src.scan.tasks.run_scanner_sync")
    def test_auto_generates_scan_id(self, mock_scan):
        """If no scan_id provided, one is generated."""
        from src.scan.tasks import run_scan

        mock_scan.return_value = []

        mock_self = MagicMock()
        result = run_scan.run.__func__(mock_self, "nginx:1.25")

        assert "scan_id" in result
        assert len(result["scan_id"]) > 0  # UUID

    @patch("src.scan.tasks.run_scanner_sync")
    @patch("src.scan.tasks.persist_findings")
    def test_save_results_false(self, mock_persist, mock_scan):
        """When save_results=False, findings are not persisted."""
        from src.scan.tasks import run_scan

        finding = _make_finding(cve="CVE-2024-0001")
        mock_scan.return_value = [(finding, "trivy")]

        mock_self = MagicMock()
        result = run_scan.run.__func__(mock_self, "nginx:1.25", save_results=False)

        assert result["persisted"] == 0
        mock_persist.assert_not_called()

    def test_unexpected_exception_is_caught(self):
        """Non-ScannerError exceptions should be caught and reported."""
        from src.scan.tasks import run_scan

        with patch("src.scan.tasks.run_scanner_sync", side_effect=RuntimeError("unexpected")):
            mock_self = MagicMock()
            result = run_scan.run.__func__(mock_self, "nginx:1.25")

            assert result["status"] == "failed"
            assert len(result["errors"]) == 2
            assert "unexpected" in result["errors"][0]["error"]

    def test_scanners_run_concurrently_and_results_keep_configured_order(self):
        """Both scanner jobs overlap while output order stays deterministic."""
        from src.scan.tasks import run_scanners_concurrently

        started = threading.Barrier(2)

        def scan_side_effect(scanner, image_name, source_name):
            started.wait(timeout=1)
            return []

        with patch("src.scan.tasks.run_scanner_sync", side_effect=scan_side_effect):
            results = run_scanners_concurrently(["trivy", "grype"], "nginx:1.25")

        assert [(name, status) for name, status, _ in results] == [
            ("trivy", "ok"),
            ("grype", "ok"),
        ]


# ---------------------------------------------------------------------------


class TestRunScannerSync:
    """Tests for the run_scanner_sync wrapper."""

    def test_returns_findings_with_source(self):
        """Helper should run scanner and add source to findings."""
        from src.scan.tasks import run_scanner_sync

        mock_scanner = MagicMock()
        mock_scanner.scan = AsyncMock(
            return_value=[
                _make_finding(cve="CVE-2024-0001"),
                _make_finding(cve="CVE-2024-0002"),
            ]
        )

        findings = run_scanner_sync(mock_scanner, "nginx:1.25", "trivy")

        assert len(findings) == 2
        assert findings[0][1] == "trivy"
        assert findings[1][1] == "trivy"
        mock_scanner.scan.assert_called_once_with("nginx:1.25")

    def test_propagates_scanner_error(self):
        """ScannerError should propagate from the helper."""
        from src.scan.tasks import run_scanner_sync

        mock_scanner = MagicMock()
        mock_scanner.scan = AsyncMock(side_effect=ScannerError("trivy", "fail", "err"))

        with pytest.raises(ScannerError):
            run_scanner_sync(mock_scanner, "nginx:1.25", "trivy")

    def test_uses_shared_sync_redis_cache(self):
        from src.scan.redis_cache import SyncRedisScanCache
        from src.scan.tasks import run_scanner_sync

        values = {}

        class Client:
            def get(self, key):
                return values.get(key)

            def set(self, key, value, ex):
                values[key] = value

        mock_scanner = MagicMock()
        mock_scanner.scan = AsyncMock(return_value=[_make_finding(cve="CVE-2024-CACHE")])
        cache = SyncRedisScanCache(Client())
        run_scanner_sync(mock_scanner, "nginx:1.25", "trivy", cache)
        run_scanner_sync(mock_scanner, "nginx:1.25", "trivy", cache)
        mock_scanner.scan.assert_awaited_once()


def test_finding_lifecycle_closes_and_reopens():
    from datetime import datetime, timezone
    from types import SimpleNamespace

    finding = SimpleNamespace(resolved_at=None, reopened_at=None)
    closed_at = datetime(2026, 11, 14, tzinfo=timezone.utc)
    apply_finding_observation(finding, observed=False, observed_at=closed_at)
    assert finding.resolved_at == closed_at

    reopened_at = datetime(2026, 11, 15, tzinfo=timezone.utc)
    apply_finding_observation(finding, observed=True, observed_at=reopened_at)
    assert finding.resolved_at is None
    assert finding.reopened_at == reopened_at
