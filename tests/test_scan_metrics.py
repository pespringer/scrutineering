from src.telemetry.scan_metrics import record_http_request, record_provider_callback, record_scan, record_scan_latency, scan_metrics, set_stale_publications


def test_scan_metrics_record_outcomes():
    scan_metrics.clear()
    record_scan("completed", "trivy")
    record_scan("cache_hit", "trivy")
    record_scan_latency(1.5, "trivy")
    output = scan_metrics.render()
    assert 'scrutineering_scans_total{scanner="trivy",status="completed"} 1' in output
    assert 'scrutineering_scans_total{scanner="trivy",status="cache_hit"} 1' in output


def test_provider_callback_metrics_record_outcomes():
    scan_metrics.clear()
    record_provider_callback("accepted")
    record_provider_callback("rollback_required")
    output = scan_metrics.render()
    assert 'scrutineering_provider_callbacks_total{outcome="accepted"} 1' in output
    assert 'scrutineering_provider_callbacks_total{outcome="rollback_required"} 1' in output


def test_stale_publication_gauge_is_rendered():
    scan_metrics.clear()
    set_stale_publications(2)
    assert "scrutineering_stale_publications 2" in scan_metrics.render()


def test_http_request_metrics_record_status_and_latency():
    scan_metrics.clear()
    record_http_request("get", "/health", 200, 0.25)
    output = scan_metrics.render()
    assert 'scrutineering_http_requests_total{method="GET",route="/health",status="200"} 1' in output
    assert 'scrutineering_http_request_duration_seconds{method="GET",route="/health",quantile="0.5"} 0.25' in output
