"""Contract tests for the authenticated dashboard data boundary."""

from datetime import datetime
from types import SimpleNamespace
import pytest
from fastapi import HTTPException

from src.analytics.dashboard_api import RemediationRequest, ScanRequest, _finding_payload, _image_payload, _page, _remediation_actions, _require_role, _scan_payload, _severity_counts
from src.db.models import AuditEventType, ImageRegistry, ScanStatus, Severity


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
        last_seen=datetime(2026, 1, 2), remediated=False, acknowledged=False, assigned_to=None,
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


def test_dashboard_page_and_scan_request_contracts():
    request = ScanRequest(image_name="  ghcr.io/acme/api:v2  ", priority="high")
    assert request.image_name == "ghcr.io/acme/api:v2"
    assert _page([{"id": 1}], limit=20, offset=0, total=41) == {
        "items": [{"id": 1}], "limit": 20, "offset": 0, "count": 1, "total": 41,
    }


def test_dashboard_roles_keep_read_only_access_separate_from_mutations():
    readonly = SimpleNamespace(state=SimpleNamespace(principal_roles=["dashboard"]))
    operator = SimpleNamespace(state=SimpleNamespace(principal_roles=["operator"]))
    _require_role(operator, "operator", "security-operator")
    with pytest.raises(HTTPException) as error:
        _require_role(readonly, "operator", "security-operator")
    assert error.value.status_code == 403


def test_cancelled_scan_event_is_part_of_the_audit_contract():
    assert AuditEventType.SCAN_CANCELLED.value == "scan_cancelled"


def test_remediation_request_is_bounded_and_preview_actions_fail_closed():
    request = RemediationRequest(image_id=4, finding_ids=[11])
    finding = SimpleNamespace(id=11, package_name="openssl", package_version="3.0.0", fixed_version=None, cve_id="CVE-2026-1", severity=Severity.HIGH, fix_available=False)
    action = _remediation_actions([finding])[0]
    assert request.finding_ids == [11]
    assert action["safe_to_apply"] is False
