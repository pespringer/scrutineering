"""Contract tests for the authenticated dashboard data boundary."""

from datetime import datetime, timedelta
from types import SimpleNamespace
import pytest
from fastapi import HTTPException

from src.analytics.dashboard_api import BackupExecutionRequest, BackupRestoreRequest, ComplianceReportRequest, DeploymentEvidenceCallbackRequest, DeploymentEvidenceRequest, FindingSuppressionRequest, PolicyRequest, RegistrySourceCheckRequest, RegistrySourceRequest, RemediationRequest, ScanRequest, ScanScheduleRequest, _finding_payload, _image_payload, _page, _remediation_actions, _require_role, _scan_payload, _schedule_payload, _severity_counts
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
        fixed_version="3.0.1", file_path="requirements.txt", fix_available=True, first_seen=datetime(2026, 1, 1),
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


def test_finding_suppression_contract_trims_reason_and_exposes_active_state():
    request = FindingSuppressionRequest(
        finding_ids=[9],
        reason="  accepted risk for the current release  ",
        expires_at=datetime.now() + timedelta(days=30),
    )
    assert request.reason == "accepted risk for the current release"

    finding = SimpleNamespace(
        id=9, image_id=7, fingerprint="fingerprint", cve_id="CVE-2026-0001",
        package_name="openssl", package_version="3.0.0", package_type="apk",
        severity=Severity.HIGH, title="Example finding", description="Details",
        fixed_version="3.0.1", file_path="requirements.txt", fix_available=True,
        first_seen=datetime(2026, 1, 1), last_seen=datetime(2026, 1, 2),
        remediated=False, acknowledged=False, assigned_to=None,
        suppressions=[SimpleNamespace(
            id=4, reason="accepted risk", created_by="operator", created_at=datetime(2026, 1, 2),
            expires_at=datetime.now() + timedelta(days=1), revoked_at=None,
        )],
    )
    payload = _finding_payload(finding)
    assert payload["suppressed"] is True
    assert payload["suppression"]["reason"] == "accepted risk"


def test_expired_or_revoked_suppression_is_not_active():
    finding = SimpleNamespace(
        id=9, image_id=7, fingerprint="fingerprint", cve_id=None,
        package_name="openssl", package_version="3.0.0", package_type="apk",
        severity=Severity.HIGH, title="Example finding", description=None,
        fixed_version=None, file_path=None, fix_available=False,
        first_seen=datetime(2026, 1, 1), last_seen=datetime(2026, 1, 2),
        remediated=False, acknowledged=False, assigned_to=None,
        suppressions=[
            SimpleNamespace(id=1, revoked_at=datetime.now(), expires_at=None),
            SimpleNamespace(id=2, revoked_at=None, expires_at=datetime.now() - timedelta(days=1)),
        ],
    )
    payload = _finding_payload(finding)
    assert payload["suppressed"] is False
    assert payload["suppression"] is None


def test_scan_schedule_contract_is_bounded_and_serializable():
    request = ScanScheduleRequest(enabled=True, interval_seconds=3600)
    assert request.interval_seconds == 3600
    assert _schedule_payload(None)["configured"] is False
    schedule = SimpleNamespace(
        id=3, enabled=True, interval_seconds=3600,
        next_run_at=datetime(2026, 1, 2), last_queued_at=None, created_by="operator",
    )
    assert _schedule_payload(schedule) == {
        "configured": True, "id": 3, "enabled": True, "interval_seconds": 3600,
        "next_run_at": "2026-01-02T00:00:00", "last_queued_at": None, "created_by": "operator",
    }
    with pytest.raises(ValueError):
        ScanScheduleRequest(interval_seconds=60)


def test_policy_request_requires_bounded_name():
    assert PolicyRequest(name="release gate", policy_type="severity_threshold", rules={"max_critical": 0}).policy_type == "severity_threshold"
    with pytest.raises(ValueError):
        PolicyRequest(name="x", policy_type="severity_threshold")


def test_compliance_report_request_limits_framework_and_format():
    request = ComplianceReportRequest(framework="soc2", output_format="markdown")
    assert request.framework == "soc2"
    assert request.output_format == "markdown"
    with pytest.raises(ValueError):
        ComplianceReportRequest(framework="iso27001")
    with pytest.raises(ValueError):
        ComplianceReportRequest(framework="nist", output_format="pdf")


def test_backup_execution_requires_explicit_confirmation():
    assert BackupExecutionRequest(confirm=True).confirm is True
    assert BackupExecutionRequest().confirm is False
    assert BackupRestoreRequest(confirm=True).confirm is True


def test_registry_source_contracts_are_secret_free_and_bounded():
    source = RegistrySourceRequest(display_name=" GHCR production ", registry_host="ghcr.io")
    assert source.display_name == "GHCR production"
    assert RegistrySourceCheckRequest(image_reference=" ghcr.io/acme/api:v1 ").image_reference == "ghcr.io/acme/api:v1"
    with pytest.raises(ValueError):
        RegistrySourceRequest(display_name="x", registry_host="https://ghcr.io")


def test_deployment_evidence_request_is_digest_only():
    request = DeploymentEvidenceRequest(
        expected_digest="sha256:" + "a" * 64,
        observed_digest="sha256:" + "a" * 64,
    )
    assert request.merge_commit is None
    callback = DeploymentEvidenceCallbackRequest(publication_id=7, **request.model_dump())
    assert callback.publication_id == 7


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


def test_remediation_preview_requires_scanner_source_coordinate():
    finding = SimpleNamespace(id=12, package_name="requests", package_version="2.0.0", fixed_version="2.0.1", cve_id="CVE-2026-2", severity=Severity.HIGH, fix_available=True, file_path="requirements.txt")
    action = _remediation_actions([finding])[0]
    assert action["file_path"] == "requirements.txt"
    assert action["safe_to_apply"] is True


def test_remediation_guidance_explains_impact_and_next_operator_action():
    finding = SimpleNamespace(
        id=14, package_name="openssl", package_version="3.0.0", fixed_version="3.0.1",
        cve_id="CVE-2026-14", severity=Severity.CRITICAL, fix_available=True,
        file_path="requirements.txt",
    )
    action = _remediation_actions([finding])[0]
    assert action["guidance"]["confidence"] == "high"
    assert "Immediate risk reduction" in action["guidance"]["impact"]
    assert "requirements.txt" in action["guidance"]["next_operator_action"]


def test_filesystem_remediation_actions_preserve_repository_directory():
    image = SimpleNamespace(registry_name=ImageRegistry.DOCKER_HUB, repo_name="local/source-fixture", tag="filesystem")
    finding = SimpleNamespace(id=13, package_name="lodash", package_version="4.17.20", fixed_version="4.18.1", cve_id="CVE-2021-23337", severity=Severity.HIGH, fix_available=True, file_path="package-lock.json")

    action = _remediation_actions([finding], image)[0]

    assert action["file_path"] == "source-fixture/package-lock.json"
    assert action["safe_to_apply"] is True
