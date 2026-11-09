"""Tests for the Celery scan orchestrator tasks."""

import uuid
import threading
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.scan.scanners.base import ScannerError, ScannerFinding
from src.scan.models import Severity


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

    @patch('src.scan.tasks.run_scanner_sync')
    @patch('src.scan.tasks.persist_findings')
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

    @patch('src.scan.tasks.run_scanner_sync')
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

    @patch('src.scan.tasks.run_scanner_sync')
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

    @patch('src.scan.tasks.run_scanner_sync')
    @patch('src.scan.tasks.persist_findings')
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

    @patch('src.scan.tasks.run_scanner_sync')
    @patch('src.scan.tasks.persist_findings')
    def test_database_persist_fails(self, mock_persist, mock_scan):
        """Scanners succeed but database persist fails — should still return partial results."""
        from src.scan.tasks import run_scan

        finding = _make_finding(cve="CVE-2024-0001")
        mock_scan.return_value = [(finding, "trivy")]
        mock_persist.side_effect = Exception("DB connection refused")

        mock_self = MagicMock()
        result = run_scan.run.__func__(mock_self, "nginx:1.25", scan_id="test-005")

        assert result["status"] == "completed"  # Scanners succeeded
        assert result["findings"] == 1
        assert len(result["errors"]) == 1
        assert result["errors"][0]["component"] == "database"

    @patch('src.scan.tasks.run_scanner_sync')
    @patch('src.scan.tasks.persist_findings')
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

    @patch('src.scan.tasks.run_scanner_sync')
    def test_auto_generates_scan_id(self, mock_scan):
        """If no scan_id provided, one is generated."""
        from src.scan.tasks import run_scan

        mock_scan.return_value = []

        mock_self = MagicMock()
        result = run_scan.run.__func__(mock_self, "nginx:1.25")

        assert "scan_id" in result
        assert len(result["scan_id"]) > 0  # UUID

    @patch('src.scan.tasks.run_scanner_sync')
    @patch('src.scan.tasks.persist_findings')
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

        with patch('src.scan.tasks.run_scanner_sync', side_effect=RuntimeError("unexpected")):
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
# Tests for run_batch_scan task
# ---------------------------------------------------------------------------

class TestRunBatchScan:
    """Tests for the run_batch_scan Celery task."""

    def test_batch_scan_multiple_images(self):
        """Batch scan processes all images and aggregates results."""
        from src.scan.tasks import run_batch_scan

        images = ["nginx:1.25", "redis:latest", "postgres:14"]

        mock_self = MagicMock()
        with patch('src.scan.tasks.run_scan') as mock_run_scan:
            mock_run_scan.side_effect = [
                {"scan_id": "batch-1", "status": "completed", "findings": 5, "findings_by_source": {"trivy": 5}, "persisted": 5, "scanners_completed": ["trivy", "grype"], "scanners_failed": [], "errors": []},
                {"scan_id": "batch-2", "status": "completed", "findings": 3, "findings_by_source": {"grype": 3}, "persisted": 3, "scanners_completed": ["trivy", "grype"], "scanners_failed": [], "errors": []},
                {"scan_id": "batch-3", "status": "partial", "findings": 1, "findings_by_source": {"trivy": 1}, "persisted": 1, "scanners_completed": ["trivy"], "scanners_failed": ["grype"], "errors": [{"scanner": "grype", "error": "timeout"}]},
            ]

            result = run_batch_scan.run.__func__(mock_self, images, scan_id_prefix="batch")

            assert result["total_images"] == 3
            assert result["total_findings"] == 9  # 5 + 3 + 1
            assert result["total_errors"] == 1  # one partial
            assert len(result["per_image_results"]) == 3

    def test_batch_scan_handles_individual_failures(self):
        """One image failing shouldn't stop the batch."""
        from src.scan.tasks import run_batch_scan

        images = ["good:latest", "bad:latest", "also-good:latest"]

        mock_self = MagicMock()
        with patch('src.scan.tasks.run_scan') as mock_run_scan:
            mock_run_scan.side_effect = [
                {"scan_id": "x-1", "status": "completed", "findings": 2, "findings_by_source": {"trivy": 2}, "persisted": 2, "scanners_completed": ["trivy"], "scanners_failed": [], "errors": []},
                {"scan_id": "x-2", "status": "failed", "findings": 0, "findings_by_source": {}, "persisted": 0, "scanners_completed": [], "scanners_failed": ["trivy", "grype"], "errors": [{"scanner": "trivy", "error": "fail"}]},
                {"scan_id": "x-3", "status": "completed", "findings": 4, "findings_by_source": {"grype": 4}, "persisted": 4, "scanners_completed": ["grype"], "scanners_failed": [], "errors": []},
            ]

            result = run_batch_scan.run.__func__(mock_self, images)

            assert result["total_findings"] == 6
            assert result["total_errors"] == 1
            assert result["per_image_results"][1]["status"] == "failed"


# ---------------------------------------------------------------------------
# Tests for run_scanner_sync helper
# ---------------------------------------------------------------------------

class TestRunScannerSync:
    """Tests for the run_scanner_sync wrapper."""

    def test_returns_findings_with_source(self):
        """Helper should run scanner and add source to findings."""
        from src.scan.tasks import run_scanner_sync

        mock_scanner = MagicMock()
        mock_scanner.scan = AsyncMock(return_value=[
            _make_finding(cve="CVE-2024-0001"),
            _make_finding(cve="CVE-2024-0002"),
        ])

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
