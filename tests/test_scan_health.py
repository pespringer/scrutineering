from src.scan.health import summarize_scan_health


def test_health_summary_counts_partial_scans_as_terminal_but_degraded():
    summary = summarize_scan_health([{"status": "completed"}, {"status": "partial"}])
    assert summary["terminal_rate"] == 1.0
    assert summary["degraded"]
