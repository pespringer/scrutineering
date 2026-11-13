#!/usr/bin/env python3
"""Run receiver-independent v1.1 checks for slices 701-900."""

from src.platform.v1_1_readiness import (
    BackupRecovery,
    CapacityModel,
    DatabaseReliability,
    ProviderLifecycleHealth,
    RegistryHealth,
    ScanReliability,
    disaster_recovery_score,
    identity_audit_gate,
    kubernetes_score,
    receiver_independent_v1_1_manifest,
    security_baseline,
    v1_1_promotion_gate,
)


def main() -> None:
    assert len(receiver_independent_v1_1_manifest()) == 200
    assert ScanReliability(1, 1, 4, False, True, True, True).result()["status"] == "ready"
    assert RegistryHealth("ghcr", 30, True, True, 10, True).result()["status"] == "healthy"
    assert DatabaseReliability(1, 4, 10, False, 0, 0.01).result()["status"] == "ready"
    assert BackupRecovery(True, True, True, True, True, 10).result()["status"] == "ready"
    assert ProviderLifecycleHealth("github", True, True, True, True, True, 1).result()["status"] == "ready"
    assert CapacityModel(1, 2, 0.3, 1, True, True).result()["recommendation"] == "steady"
    assert identity_audit_gate(api_keys_current=True, services_rotated=True, tenant_isolation=True, role_snapshots_current=True, audit_chain_valid=True, privileged_actions_confirmed=True)["status"] == "ready"
    assert security_baseline(dependency_evidence=True, capabilities_restricted=True, digests_fresh=True, secrets_clean=True, network_policies=True, quotas_valid=True, filesystem_restricted=True)["status"] == "ready"
    assert disaster_recovery_score(redis=True, postgres=True, worker=True, scheduler=True, registry=True, provider=True, backup=True, dashboard=True)["status"] == "passed"
    assert kubernetes_score(rollout=True, image_pull=True, quota=True, disruption=True, network=True, service_account=True, storage=True, drift=True)["status"] == "ready"
    kwargs = {key: True for key in ("scan", "backup", "database", "provider", "dashboard", "telemetry", "capacity", "identity", "security", "recovery", "kubernetes", "compliance", "performance")}
    assert v1_1_promotion_gate(**kwargs)["promotion"]
    print("v1.1 readiness drill: scan, registry, database, recovery, security, Kubernetes, and promotion checks passed")


if __name__ == "__main__":
    main()

