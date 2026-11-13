from src.platform.production_maturity import (
    BackupDestinationHealth,
    DatabaseQuality,
    DashboardReport,
    ProviderReadiness,
    RestoreRequest,
    ScanOrchestration,
    ScalingObservation,
    documentation_freshness,
    failure_rate,
    identity_security_score,
    percentile_metrics,
    promotion_gate,
    publication_replay_key,
    receiver_independent_maturity_manifest,
    reproducibility_check,
    scan_orchestration_report,
)


def test_scan_orchestration_and_reproducibility():
    config = ScanOrchestration("tenant-a", "normal", 4, 60, "trivy-1", "db-1")
    assert scan_orchestration_report(config, queued=3, suppressed=1, retried=0)["queued"] == 3
    assert reproducibility_check(expected_digest="a", actual_digest="a", expected_findings=2, actual_findings=2)["reproducible"]


def test_backup_restore_and_provider_readiness():
    assert BackupDestinationHealth("s3", True, True, 10, 2).result()["status"] == "healthy"
    assert RestoreRequest("r1", "operator", "backup", "isolated", True, True).audit()["execute"] is True
    assert ProviderReadiness("github", 30, True, True, "policy").result()["status"] == "ready"


def test_dashboard_metrics_and_database_quality():
    assert DashboardReport("findings", "operator", (("severity", "high"),), 2).result()["rows"] == 2
    assert percentile_metrics([1, 2, 3])["p95"] >= 2
    assert failure_rate(10, 2) == 0.2
    assert DatabaseQuality(10, 0, 0, 1, 0.5).result()["status"] == "healthy"


def test_scaling_security_docs_and_promotion_gate():
    assert ScalingObservation(100, 2, 12, True).result()["recommendation"] == "scale_out"
    assert identity_security_score(keys_current=True, tenants_isolated=True, roles_current=True, audit_integrity=True, redaction_verified=True)["status"] == "ready"
    assert documentation_freshness(required_paths=["README.md"], missing_paths=[], stale_paths=[])["status"] == "ready"
    assert promotion_gate(api_latency={"p95": 1}, scan_throughput=1, backup_throughput=1, restore_throughput=1, migration_passed=True, load_test_passed=True, evidence_package=True)["status"] == "ready"


def test_replay_key_and_manifest():
    assert len(publication_replay_key("github", 1, "request")) == 64
    manifest = receiver_independent_maturity_manifest()
    assert len(manifest) == 100
    assert manifest[0]["slice"] == 501 and manifest[-1]["slice"] == 600
    assert all(item["receiver_required"] is False for item in manifest)

