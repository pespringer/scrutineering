#!/usr/bin/env python3
"""Run receiver-independent v1.0 readiness checks for slices 601-700."""

from src.platform.v1_readiness import (
    BackupFailoverPlan,
    DatabaseForecast,
    ProviderLifecycle,
    ScanPlatformState,
    ScalingDecision,
    identity_security_gate,
    receiver_independent_v1_manifest,
    v1_promotion_gate,
)


def main() -> None:
    assert len(receiver_independent_v1_manifest()) == 100
    assert ScanPlatformState("tenant", 1, 1, 4, True, True, True, True).result()["status"] == "ready"
    assert BackupFailoverPlan("primary", "secondary", True, True, True, True).result()["status"] == "ready"
    assert ProviderLifecycle("github", 30, True, True, True, True).result()["status"] == "ready"
    assert DatabaseForecast(10, 1, 30, 0, 0, 0.4).result()["quality"] == "healthy"
    assert ScalingDecision(1, 2, 0.3, 0, False).result()["recommendation"] == "steady"
    assert identity_security_gate(service_keys_current=True, api_keys_expiring=False, tenants_isolated=True, roles_current=True, audit_valid=True, redaction_valid=True, container_restricted=True)["status"] == "ready"
    assert v1_promotion_gate(api_latency_passed=True, scan_benchmark_passed=True, backup_benchmark_passed=True, restore_benchmark_passed=True, provider_benchmark_passed=True, migration_passed=True, load_test_passed=True, evidence_package_ready=True)["promotion"]
    print("v1 readiness drill: scan, backup, provider, database, scaling, security, and promotion checks passed")


if __name__ == "__main__":
    main()

