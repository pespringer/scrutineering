from src.platform.v1_readiness import (
    BackupFailoverPlan,
    DashboardView,
    DatabaseForecast,
    ProviderLifecycle,
    RestoreLifecycle,
    ScanPlatformState,
    ScalingDecision,
    documentation_inventory,
    identity_security_gate,
    receiver_independent_v1_manifest,
    scan_replay_key,
    telemetry_query,
    v1_promotion_gate,
)


def test_scan_platform_and_replay():
    assert ScanPlatformState("tenant", 2, 1, 4, True, True, True, True).result()["status"] == "ready"
    assert len(scan_replay_key("scan", "trivy", "db")) == 64


def test_backup_restore_and_provider_lifecycle():
    assert BackupFailoverPlan("primary", "secondary", True, True, True, True).result()["status"] == "ready"
    assert RestoreLifecycle("r1", "verified", 100, 3, 3).result()["ready"] is True
    assert ProviderLifecycle("github", 30, True, True, True, True).result()["status"] == "ready"


def test_dashboard_telemetry_database_and_scaling():
    assert DashboardView("posture", "operator", (("severity", "high"),), "json").result()["row_limit"] == 1000
    assert telemetry_query("latency", "start", "end", "p95")["bounded"] is True
    assert DatabaseForecast(10, 1, 30, 0, 0, 0.4).result()["projected_gb"] == 40
    assert ScalingDecision(100, 2, 0.9, 10, False).result()["recommendation"] == "scale_out"


def test_security_docs_and_v1_gate():
    assert identity_security_gate(service_keys_current=True, api_keys_expiring=False, tenants_isolated=True, roles_current=True, audit_valid=True, redaction_valid=True, container_restricted=True)["status"] == "ready"
    assert documentation_inventory(["README.md"], [], [])["status"] == "ready"
    assert v1_promotion_gate(api_latency_passed=True, scan_benchmark_passed=True, backup_benchmark_passed=True, restore_benchmark_passed=True, provider_benchmark_passed=True, migration_passed=True, load_test_passed=True, evidence_package_ready=True)["promotion"] is True


def test_manifest_has_100_receiver_independent_slices():
    manifest = receiver_independent_v1_manifest()
    assert len(manifest) == 100
    assert manifest[0]["slice"] == 601 and manifest[-1]["slice"] == 700
    assert all(item["receiver_required"] is False for item in manifest)

