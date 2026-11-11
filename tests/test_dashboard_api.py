"""Contract tests for the authenticated dashboard data boundary."""

from datetime import datetime
from types import SimpleNamespace

from src.analytics.dashboard_api import _finding_payload, _image_payload, _scan_payload, _severity_counts
from src.db.models import ImageRegistry, ScanStatus, Severity


def test_dashboard_serializers_match_frontend_contract():
    image = SimpleNamespace(
        id=7, registry_name=ImageRegistry.GHCR, repo_name="acme/api", tag="v1",
        last_scan_at=datetime(2026, 1, 2, 3, 4, 5), last_scan_id="scan-7",
        full_name="ghcr/acme/api:v1",
    )
    finding = SimpleNamespace(
        id=9, image_id=7, fingerprint="fingerprint", cve_id="CVE-2026-0001",
        package_name="openssl", package_version="3.0.0", package_type="apk",
        severity=Severity.HIGH, title="Example finding", description="Details",
        fixed_version="3.0.1", fix_available=True, first_seen=datetime(2026, 1, 1),
        last_seen=datetime(2026, 1, 2), remediated=False,
    )
    scan = SimpleNamespace(
        scan_id="scan-7", image=image, status=ScanStatus.COMPLETED,
        started_at=datetime(2026, 1, 2), completed_at=datetime(2026, 1, 2, 0, 5),
        total_findings=1, critical_count=0, high_count=1, medium_count=0, low_count=0,
    )

    assert _severity_counts([finding]) == {"critical": 0, "high": 1, "medium": 0, "low": 0}
    assert _image_payload(image, [finding])["open_findings"] == 1
    assert _scan_payload(scan)["status"] == "completed"
    assert _finding_payload(finding)["severity"] == "HIGH"
