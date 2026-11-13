from src.platform.release_health import HealthCheck, evaluate_release_health, evaluate_slo
from src.remediation.provider_diagnostics import classify_provider_outage, diagnose_capabilities, provider_request_outcome, required_permissions
from src.telemetry.scan_metrics import record_provider_request, record_slo, scan_metrics, set_backup_last_success, set_queue_health


def test_provider_capability_diagnostics_are_explicit_and_bounded():
    assert required_permissions("github")
    result = diagnose_capabilities("github", {"pull_requests:read"})
    assert result.can_read is True
    assert result.can_create is False
    assert "pull_requests:write" in result.missing_permissions
    assert classify_provider_outage("HTTP 429 too many requests") == "rate_limited"
    assert provider_request_outcome(503) == "unavailable"


def test_release_health_fails_closed_only_on_required_checks():
    result = evaluate_release_health([HealthCheck("database", True), HealthCheck("optional-telemetry", False, required=False)])
    assert result["status"] == "ready"
    assert evaluate_release_health([HealthCheck("database", False)])["status"] == "blocked"
    assert evaluate_slo(name="queue_latency", observed=2, target=5)["passed"] is True


def test_operational_metrics_cover_queue_backup_provider_and_slo():
    scan_metrics.clear()
    set_queue_health("scan.normal", 2, 30)
    set_backup_last_success(100)
    record_provider_request("github", "success")
    record_slo("scan_success", 0.99, 0.95, True)
    snapshot = scan_metrics.snapshot()
    assert any("scrutineering_queue_depth" in key for key in snapshot["gauges"])
    assert any("scrutineering_backup_last_success_timestamp" in key for key in snapshot["gauges"])
    assert any("scrutineering_provider_requests_total" in key for key in snapshot["counters"])
