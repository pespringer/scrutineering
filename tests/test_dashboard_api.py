"""Contract tests for the authenticated dashboard data boundary."""

from datetime import datetime
from types import SimpleNamespace
import pytest
from fastapi import HTTPException

from src.analytics.dashboard_api import DeploymentEvidenceCallbackRequest, DeploymentEvidenceRequest, RemediationRequest, ScanRequest, _finding_payload, _image_payload, _local_registry_public_url, _page, _remediation_actions, _remediation_payload, _remediation_workflow_state, _require_role, _scan_payload, _severity_counts
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
        last_seen=datetime(2026, 1, 2), remediated=False, acknowledged=False, assigned_to=None, remediation_id=None,
    )
    scan = SimpleNamespace(
        scan_id="scan-7", image=image, status=ScanStatus.COMPLETED,
        started_at=datetime(2026, 1, 2), completed_at=datetime(2026, 1, 2, 0, 5),
        total_findings=1, critical_count=0, high_count=1, medium_count=0, low_count=0,
    )

    assert _severity_counts([finding]) == {"critical": 0, "high": 1, "medium": 0, "low": 0}
    assert _image_payload(image, [finding])["open_findings"] == 1
    assert _image_payload(image, [finding], resolved_count=2)["resolved_findings"] == 2
    assert _scan_payload(scan)["status"] == "completed"
    assert _finding_payload(finding)["severity"] == "HIGH"
    assert _finding_payload(finding)["remediation_id"] is None


def test_remediation_serializer_exposes_open_and_resolved_counts():
    remediation = SimpleNamespace(
        id=3, image_id=7, status="completed", finding_count=2,
        target_severities=["high"], approved_by=None, approved_at=None,
        findings=[SimpleNamespace(resolved_at=None), SimpleNamespace(resolved_at=datetime(2026, 1, 3))],
        publications=[], actions=[],
    )

    payload = _remediation_payload(remediation)

    assert payload["open_finding_count"] == 1
    assert payload["resolved_finding_count"] == 1
    assert payload["resolution_status"] == "open"


def test_remediation_serializer_exposes_operator_workflow_state():
    remediation = SimpleNamespace(
        id=4, image_id=7, status="analyzing", finding_count=1,
        target_severities=["high"], approved_by=None, approved_at=None,
        findings=[SimpleNamespace(resolved_at=None)], publications=[], actions=[],
        events=[SimpleNamespace(event_type="execution_ready")],
    )

    payload = _remediation_payload(remediation)

    assert payload["workflow_state"] == "execution_ready"
    assert payload["workflow_label"] == "Execution ready"


@pytest.mark.parametrize(
    "event_type,expected",
    [
        ("execution_queued", "execution_queued"),
        ("execution_started", "execution_started"),
        ("execution_ready", "execution_ready"),
        ("execution_blocked", "execution_blocked"),
    ],
)
def test_remediation_workflow_state_tracks_execution_events(event_type, expected):
    remediation = SimpleNamespace(status="analyzing")
    assert _remediation_workflow_state(remediation, [SimpleNamespace(event_type=event_type)]) == expected


def test_dashboard_page_and_scan_request_contracts():
    request = ScanRequest(image_name="  ghcr.io/acme/api:v2  ", priority="high")
    assert request.image_name == "ghcr.io/acme/api:v2"
    assert _page([{"id": 1}], limit=20, offset=0, total=41) == {
        "items": [{"id": 1}], "limit": 20, "offset": 0, "count": 1, "total": 41,
    }


def test_registry_dashboard_uses_public_host_for_browser_links(monkeypatch):
    monkeypatch.delenv("LOCAL_REGISTRY_PUBLIC_URL", raising=False)
    monkeypatch.setenv("LOCAL_REGISTRY_PUBLIC_HOST", "registry.example.test:5443")
    monkeypatch.setenv("REGISTRY_INSECURE", "false")

    assert _local_registry_public_url() == "https://registry.example.test:5443"

    monkeypatch.setenv("LOCAL_REGISTRY_PUBLIC_URL", "http://localhost:5000/")
    assert _local_registry_public_url() == "http://localhost:5000"


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


def test_remediation_actions_reject_fix_without_explicit_source_path():
    finding = SimpleNamespace(id=14, package_name="openssl", package_version="3.0.0", fixed_version="3.0.1", cve_id="CVE-2026-3", severity=Severity.HIGH, fix_available=True, file_path=None)
    action = _remediation_actions([finding])[0]
    assert action["safe_to_apply"] is False


def test_filesystem_remediation_actions_preserve_repository_directory():
    image = SimpleNamespace(registry_name=ImageRegistry.DOCKER_HUB, repo_name="local/source-fixture", tag="filesystem")
    finding = SimpleNamespace(id=13, package_name="lodash", package_version="4.17.20", fixed_version="4.18.1", cve_id="CVE-2021-23337", severity=Severity.HIGH, fix_available=True, file_path="package-lock.json")

    action = _remediation_actions([finding], image)[0]

    assert action["file_path"] == "source-fixture/package-lock.json"
    assert action["safe_to_apply"] is True
