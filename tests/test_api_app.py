from src.api.app import app


KEPT_ROUTES = {
    "/health", "/ready", "/metrics", "/version",
    "/api/dashboard/posture/summary", "/api/dashboard/posture/trend",
    "/api/dashboard/scans", "/api/dashboard/scans/{scan_id}", "/api/dashboard/scans/{scan_id}/cancel",
    "/api/dashboard/scans/{scan_id}/findings", "/api/dashboard/images", "/api/dashboard/images/{image_id}",
    "/api/dashboard/registry/inventory", "/api/dashboard/session", "/api/dashboard/permissions",
    "/api/dashboard/audit", "/api/dashboard/remediations/preview", "/api/dashboard/remediations",
    "/api/dashboard/remediations/{remediation_id}", "/api/dashboard/remediations/{remediation_id}/approve",
    "/api/dashboard/remediations/{remediation_id}/execute", "/api/dashboard/remediations/{remediation_id}/retry",
    "/api/dashboard/remediations/{remediation_id}/events", "/api/dashboard/webhooks/{provider}",
}

REMOVED_ROUTE_FRAGMENTS = (
    "approval-token", "publication-plan", "/publish", "post-merge/verify", "recovery", "reconciliation",
    "deployment-evidence", "deployment-observation", "alert-", "evidence-export", "/evidence",
    "provider-credentials", "provider-diagnostics", "release-health", "production-operations",
)


def test_canonical_api_composes_health_and_dashboard_routes():
    paths = set(app.openapi()["paths"])
    assert KEPT_ROUTES <= paths
    assert not any(path.startswith(("/api/v1", "/api/runtime", "/api/forensics", "/api/analytics")) for path in paths)
    assert not [path for path in paths if any(fragment in path for fragment in REMOVED_ROUTE_FRAGMENTS)]


def test_service_auth_configuration_accepts_body_bound_internal_requests(monkeypatch):
    from src.api.app import is_service_request_authorized
    from src.api.service_auth import create_replay_guard, sign_service_request

    monkeypatch.setenv("SERVICE_AUTH_SECRET", "internal-secret")
    monkeypatch.setenv("SERVICE_AUTH_REQUIRED", "true")
    headers = sign_service_request("scanner", b"{}", "internal-secret")

    guard = create_replay_guard()
    assert is_service_request_authorized(headers, b"{}", "internal-secret", guard)
    assert not is_service_request_authorized(headers, b"{}", "internal-secret", guard)


def test_provider_webhook_path_uses_hmac_boundary():
    from src.api.app import is_provider_webhook_path

    assert is_provider_webhook_path("/api/dashboard/webhooks/github")
    assert is_provider_webhook_path("/api/dashboard/webhooks/gitlab")
    assert is_provider_webhook_path("/api/dashboard/deployment-evidence")
    assert not is_provider_webhook_path("/api/dashboard/remediations")
    assert not is_provider_webhook_path("/api/dashboard/webhooks/github/extra")
