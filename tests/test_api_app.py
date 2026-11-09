from src.api.app import app


def test_canonical_api_composes_health_and_versioned_routes():
    paths = set(app.openapi()["paths"])
    assert "/health" in paths
    assert "/metrics" in paths
    assert "/api/v1/findings" in paths
    assert "/api/runtime/overview" in paths
    assert "/api/forensics/snapshot" in paths
    assert "/api/v1/scans/{scan_id}" in paths
