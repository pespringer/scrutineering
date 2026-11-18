from src.api.app import app


KEPT_ROUTES = {
    "/health",
    "/ready",
    "/metrics",
    "/version",
    "/api/dashboard/posture/summary",
    "/api/dashboard/posture/trend",
    "/api/dashboard/scans",
    "/api/dashboard/scans/{scan_id}",
    "/api/dashboard/scans/{scan_id}/cancel",
    "/api/dashboard/scans/{scan_id}/findings",
    "/api/dashboard/images",
    "/api/dashboard/images/{image_id}",
    "/api/dashboard/remediations/{remediation_id}/publish",
    "/api/dashboard/registry/inventory",
    "/api/dashboard/session",
    "/api/dashboard/permissions",
    "/api/dashboard/audit",
    "/api/dashboard/remediations/preview",
    "/api/dashboard/remediations",
    "/api/dashboard/remediations/{remediation_id}",
    "/api/dashboard/remediations/{remediation_id}/approve",
    "/api/dashboard/remediations/{remediation_id}/execute",
    "/api/dashboard/remediations/{remediation_id}/retry",
    "/api/dashboard/remediations/{remediation_id}/events",
    "/api/dashboard/webhooks/{provider}",
    "/api/dashboard/system-status",
}

REMOVED_ROUTE_FRAGMENTS = (
    "approval-token",
    "publication-plan",
    "/publish-",
    "publications/",
    "post-merge/verify",
    "recovery",
    "reconciliation",
    "deployment-evidence",
    "deployment-observation",
    "alert-",
    "evidence-export",
    "provider-credentials",
    "provider-diagnostics",
    "release-health",
    "production-operations",
)


def test_canonical_api_composes_health_and_dashboard_routes():
    paths = set(app.openapi()["paths"])
    assert KEPT_ROUTES <= paths
    assert not any(path.startswith(("/api/v1", "/api/runtime", "/api/forensics", "/api/analytics")) for path in paths)
    assert not [path for path in paths if any(fragment in path for fragment in REMOVED_ROUTE_FRAGMENTS)]
    # Evidence is built by the server (docs/design/sbom-evidence.md); no route may accept it from a client.
    evidence = {path: set(methods) for path, methods in app.openapi()["paths"].items() if "/evidence" in path}
    assert evidence and all(methods == {"get"} for methods in evidence.values()), evidence


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
    assert not is_provider_webhook_path("/api/dashboard/webhooks/gitlab")
    assert is_provider_webhook_path("/api/dashboard/deployment-evidence")
    assert not is_provider_webhook_path("/api/dashboard/remediations")
    assert not is_provider_webhook_path("/api/dashboard/webhooks/github/extra")
