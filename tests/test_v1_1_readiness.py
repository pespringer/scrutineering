from src.platform.v1_1_readiness import (
    BackupRecovery,
    CapacityModel,
    DatabaseReliability,
    DashboardAccessibility,
    ProviderLifecycleHealth,
    RegistryHealth,
    ScanReliability,
    compliance_traceability,
    disaster_recovery_score,
    identity_audit_gate,
    kubernetes_score,
    lifecycle_quality,
    receiver_independent_v1_1_manifest,
    security_baseline,
    slo_score,
    v1_1_promotion_gate,
)


def test_scan_registry_and_database_contracts():
    assert ScanReliability(2, 1, 4, False, True, True, True).result()["status"] == "ready"
    assert RegistryHealth("ghcr", 30, True, True, 10, True).result()["status"] == "healthy"
    assert DatabaseReliability(2, 4, 10, False, 0, 0.01).result()["status"] == "ready"


def test_backup_provider_and_publication_contracts():
    assert BackupRecovery(True, True, True, True, True, 10).result()["status"] == "ready"
    assert ProviderLifecycleHealth("github", True, True, True, True, True, 1).result()["status"] == "ready"
    assert lifecycle_quality(orphaned=0, duplicate_images=0, duplicate_findings=0, retention_verified=True)["status"] == "healthy"


def test_dashboard_telemetry_slo_and_capacity_contracts():
    assert DashboardAccessibility(True, True, True, True, 1000, True).result()["status"] == "ready"
    assert slo_score(scan=True, queue=True, worker=True, provider=True, backup=True, restore=True, tenant=True)["status"] == "ready"
    assert CapacityModel(1, 2, 0.3, 1, True, True).result()["recommendation"] == "steady"


def test_security_recovery_kubernetes_and_compliance():
    assert identity_audit_gate(api_keys_current=True, services_rotated=True, tenant_isolation=True, role_snapshots_current=True, audit_chain_valid=True, privileged_actions_confirmed=True)["status"] == "ready"
    assert security_baseline(dependency_evidence=True, capabilities_restricted=True, digests_fresh=True, secrets_clean=True, network_policies=True, quotas_valid=True, filesystem_restricted=True)["status"] == "ready"
    assert disaster_recovery_score(redis=True, postgres=True, worker=True, scheduler=True, registry=True, provider=True, backup=True, dashboard=True)["status"] == "passed"
    assert kubernetes_score(rollout=True, image_pull=True, quota=True, disruption=True, network=True, service_account=True, storage=True, drift=True)["status"] == "ready"
    assert compliance_traceability(controls=2, tested=2, evidence=2, retention=True, access_review=True)["status"] == "ready"


def test_v1_1_gate_and_manifest():
    kwargs = {key: True for key in ("scan", "backup", "database", "provider", "dashboard", "telemetry", "capacity", "identity", "security", "recovery", "kubernetes", "compliance", "performance")}
    assert v1_1_promotion_gate(**kwargs)["promotion"] is True
    manifest = receiver_independent_v1_1_manifest()
    assert len(manifest) == 200
    assert manifest[0]["slice"] == 701 and manifest[-1]["slice"] == 900
    assert all(item["receiver_required"] is False for item in manifest)

