from src.telemetry.prometheus import MetricsRegistry


def test_metrics_registry_renders_counters_and_gauges():
    metrics = MetricsRegistry()
    metrics.increment("scan_total", labels={"status": "completed"})
    metrics.set_gauge("scanner_queue_depth", 3)
    metrics.observe("scan_latency_seconds", 1)
    metrics.observe("scan_latency_seconds", 3)
    output = metrics.render()
    assert 'scan_total{status="completed"} 1' in output
    assert "scanner_queue_depth 3" in output
    assert metrics.snapshot()["gauges"]["scanner_queue_depth|"] == 3
    assert 'scan_latency_seconds{quantile="0.95"} 3' in output
    assert "scan_latency_seconds_count 2" in output
