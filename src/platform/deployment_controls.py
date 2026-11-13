"""Deployment and container safety checks used by release gates."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class DeploymentCheck:
    name: str
    passed: bool
    detail: str


def validate_image_pin(reference: str) -> DeploymentCheck:
    return DeploymentCheck("image_digest_pin", bool(re.fullmatch(r"[^@\s]+@sha256:[a-f0-9]{64}", reference)), "digest-pinned" if "@sha256:" in reference else "mutable image reference")


def validate_secret_mounts(names: list[str]) -> DeploymentCheck:
    safe = all(name and re.fullmatch(r"[A-Za-z0-9._-]{1,128}", name) for name in names)
    return DeploymentCheck("secret_mounts", safe, "validated" if safe else "invalid secret name")


def validate_container_security(*, run_as_non_root: bool, read_only_root: bool, privilege_escalation: bool) -> DeploymentCheck:
    passed = run_as_non_root and read_only_root and not privilege_escalation
    return DeploymentCheck("container_security", passed, "restricted" if passed else "container security policy is incomplete")


def validate_resources(cpu_millicores: int, memory_mb: int) -> DeploymentCheck:
    passed = cpu_millicores > 0 and memory_mb > 0
    return DeploymentCheck("resource_limits", passed, "bounded" if passed else "resource limits are required")


def configuration_drift(expected: dict[str, str], observed: dict[str, str]) -> dict[str, object]:
    changed = sorted(key for key in set(expected) | set(observed) if expected.get(key) != observed.get(key))
    return {"drift": bool(changed), "changed": changed, "safe": not changed}


def rollout_health(*, desired: int, ready: int, unavailable: int = 0) -> dict[str, object]:
    if min(desired, ready, unavailable) < 0:
        raise ValueError("rollout counts must not be negative")
    return {"ready": desired > 0 and ready >= desired and unavailable == 0, "desired": desired, "ready_count": ready, "unavailable": unavailable}
