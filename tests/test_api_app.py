from src.api.app import app


def test_canonical_api_composes_health_and_versioned_routes():
    paths = set(app.openapi()["paths"])
    assert "/health" in paths
    assert "/ready" in paths
    assert "/metrics" in paths
    assert "/api/v1/findings" in paths
    assert "/api/runtime/overview" in paths
    assert "/api/forensics/snapshot" in paths
    assert "/api/v1/scans/{scan_id}" in paths


def test_service_auth_configuration_accepts_body_bound_internal_requests(monkeypatch):
    from src.api.app import is_service_request_authorized
    from src.api.service_auth import create_replay_guard, sign_service_request

    monkeypatch.setenv("SERVICE_AUTH_SECRET", "internal-secret")
    monkeypatch.setenv("SERVICE_AUTH_REQUIRED", "true")
    headers = sign_service_request("scanner", b"{}", "internal-secret")

    guard = create_replay_guard()
    assert is_service_request_authorized(headers, b"{}", "internal-secret", guard)
    assert not is_service_request_authorized(headers, b"{}", "internal-secret", guard)
