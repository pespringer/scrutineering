from src.telemetry.scan_metrics import record_provider_callback, record_scan, record_scan_latency, scan_metrics


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
