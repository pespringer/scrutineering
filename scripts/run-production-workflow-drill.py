#!/usr/bin/env python3
"""Run deterministic receiver-independent workflow checks for slices 401-500."""

from datetime import datetime, timezone

from src.platform.production_workflows import (
    BackupSchedule,
    DeploymentPoll,
    LiveScanEvidenceBundle,
    ProviderConformance,
    RecoveryScenario,
    RestoreVerification,
    backup_schedule_readiness,
    build_scan_evidence,
    post_merge_evidence,
    receiver_independent_workflow_manifest,
    recovery_time_report,
    release_security_evidence,
)


def main() -> None:
    assert len(receiver_independent_workflow_manifest()) == 100
    assert build_scan_evidence(LiveScanEvidenceBundle("s1", "alpine:3.20", "completed", True, True, False))["status"] == "passed"
    assert backup_schedule_readiness(BackupSchedule("daily", "daily", "local://backup", True, True))["ready"]
    assert RestoreVerification("isolated", 1, 1, "a", "a", True).result()["status"] == "passed"
    assert ProviderConformance("github", True, True, True, True, True, True).report()["status"] == "passed"
    assert post_merge_evidence(DeploymentPoll(1, 1, "sha256:a", "sha256:a", "completed", 0))["decision"] == "verified"
    assert recovery_time_report([RecoveryScenario("redis", True, True, 1)], 5)["status"] == "passed"
    assert release_security_evidence(digests=True, secrets=True, drift=True, quota=True, accessibility=True, contracts=True, runbooks=True)["status"] == "ready"
    print("production workflow drill: scan, backup, restore, provider, publication, recovery, and release checks passed")


if __name__ == "__main__":
    main()

