"""Configuration parsing for provider-neutral deployment observation."""

from __future__ import annotations

import json
import os

from src.remediation.deployment_collectors import DeploymentCollectorError


def configured_deployment_target(repository: str, raw: str | None = None) -> dict:
    """Resolve a repository to an explicit, validated runtime target."""
    value = raw if raw is not None else os.environ.get("DEPLOYMENT_COLLECTOR_TARGETS_JSON", "{}")
    try:
        targets = json.loads(value)
    except json.JSONDecodeError as exc:
        raise DeploymentCollectorError("deployment collector target configuration is invalid JSON") from exc
    target = targets.get(repository)
    if not isinstance(target, dict) or target.get("provider") not in {"docker", "kubernetes"}:
        raise DeploymentCollectorError(f"no deployment collector target configured for {repository}")
    if target["provider"] == "docker" and not target.get("container"):
        raise DeploymentCollectorError("docker collector target requires container")
    if target["provider"] == "kubernetes" and (not target.get("namespace") or not target.get("selector")):
        raise DeploymentCollectorError("kubernetes collector target requires namespace and selector")
    if target["provider"] == "kubernetes" and target.get("workload") is not None:
        workload = target["workload"]
        if not isinstance(workload, str) or not workload or any(char.isspace() for char in workload):
            raise DeploymentCollectorError("kubernetes workload must be a non-empty name")
    return target
