"""Final receiver-independent production promotion gate."""

from __future__ import annotations


def production_promotion_gate(*, tests_passed: bool, migrations_valid: bool, deployment_valid: bool, backup_fresh: bool, recovery_ready: bool, configuration_clean: bool) -> dict[str, object]:
    checks = {"tests": tests_passed, "migrations": migrations_valid, "deployment": deployment_valid, "backup": backup_fresh, "recovery": recovery_ready, "configuration": configuration_clean}
    blocking = [name for name, passed in checks.items() if not passed]
    return {"status": "ready" if not blocking else "blocked", "checks": checks, "blocking": blocking}
