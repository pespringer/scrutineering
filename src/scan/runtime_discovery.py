"""Runtime container discovery helpers for scan scheduling."""

from __future__ import annotations

import fnmatch
import os
from typing import Any

from src.scan.image_identity import parse_image_reference


_SAFE_CONTEXT_LABELS = {
    "com.docker.compose.project": "project",
    "com.docker.compose.service": "service",
    "com.docker.compose.container-number": "replica",
    "io.kubernetes.pod.name": "pod",
    "io.kubernetes.container.name": "container",
    "io.kubernetes.namespace": "namespace",
    "k8s.namespace.name": "namespace",
    "namespace": "namespace",
    "app.kubernetes.io/name": "workload",
    "app.kubernetes.io/part-of": "owner",
    "app": "workload",
}


def _patterns(name: str) -> list[str]:
    return [item.strip() for item in os.environ.get(name, "").split(",") if item.strip()]


def _labels_match(labels: Any, expression: str | None) -> bool:
    if not expression:
        return True
    key, separator, expected = expression.partition("=")
    if not separator or not key:
        return False
    if isinstance(labels, str):
        labels = dict(item.split("=", 1) for item in labels.split(",") if "=" in item)
    return isinstance(labels, dict) and labels.get(key) == expected


def is_scannable_runtime_image(image: str) -> bool:
    """Reject runtime metadata that cannot be passed to an OCI scanner.

    Docker/containerd inventories can contain local filesystem aliases and
    content-addressable IDs. Those values are useful runtime metadata, but
    they are not pullable image references for the scanner adapters.
    """
    value = str(image or "").strip()
    if not value or value.startswith("sha256:"):
        return False
    if ":filesystem" in value or ":/" in value or "/workspace/" in value:
        return False
    if ".invalid/" in value:
        return False
    try:
        identity = parse_image_reference(value)
    except ValueError:
        return False
    return bool(identity.repo_name and identity.tag and identity.tag != "filesystem")


def safe_runtime_context(container: dict[str, Any]) -> dict[str, str]:
    """Return only known, non-secret workload coordinates for the dashboard."""
    context: dict[str, str] = {}
    for field in ("namespace", "workload", "owner"):
        value = str(container.get(field) or "").strip()
        if value:
            context[field] = value[:128]
    labels = container.get("labels")
    if isinstance(labels, str):
        labels = dict(item.split("=", 1) for item in labels.split(",") if "=" in item)
    if isinstance(labels, dict):
        for label, field in _SAFE_CONTEXT_LABELS.items():
            value = str(labels.get(label) or "").strip()
            if value and field not in context:
                context[field] = value[:128]
    return context


def select_runtime_images(containers: list[dict[str, Any]], *, include: list[str] | None = None,
                         exclude: list[str] | None = None, exclude_containers: list[str] | None = None,
                         include_label: str | None = None, limit: int = 100) -> list[str]:
    """Return stable, unique image references selected from running containers."""
    if limit < 1:
        raise ValueError("runtime discovery limit must be positive")
    include = include if include is not None else _patterns("SCAN_RUNTIME_INCLUDE_IMAGES")
    exclude = exclude if exclude is not None else _patterns("SCAN_RUNTIME_EXCLUDE_IMAGES")
    exclude_containers = exclude_containers if exclude_containers is not None else _patterns("SCAN_RUNTIME_EXCLUDE_CONTAINERS")
    include_label = include_label if include_label is not None else os.environ.get("SCAN_RUNTIME_INCLUDE_LABEL")
    selected: list[str] = []
    seen: set[str] = set()
    for container in containers:
        image = str(container.get("image") or "").strip()
        name = str(container.get("names") or container.get("id") or "").strip()
        if not is_scannable_runtime_image(image) or not _labels_match(container.get("labels"), include_label):
            continue
        if exclude_containers and any(fnmatch.fnmatchcase(name, pattern) for pattern in exclude_containers):
            continue
        if include and not any(fnmatch.fnmatchcase(image, pattern) for pattern in include):
            continue
        if exclude and any(fnmatch.fnmatchcase(image, pattern) for pattern in exclude):
            continue
        if image not in seen:
            seen.add(image)
            selected.append(image)
        if len(selected) >= limit:
            break
    return selected


async def discover_runtime_containers(*, use_containerd: bool = False,
                                      docker_bin: str = "docker", ctr_bin: str = "ctr",
                                      containerd_namespace: str = "default") -> list[dict[str, Any]]:
    """Discover containers and enrich containerd records with image names."""
    if use_containerd:
        from src.runtime.containerd_monitor import ContainerdCollector
        collector = ContainerdCollector(ctr_bin=ctr_bin, namespace=containerd_namespace)
    else:
        from src.runtime.docker_monitor import DockerRuntimeCollector
        collector = DockerRuntimeCollector(docker_bin=docker_bin)
    containers = await collector.list_running_containers()
    if use_containerd:
        for container in containers:
            if not container.get("image"):
                info = await collector.get_container_info(container["id"])
                if info:
                    container["image"] = info.get("image") or info.get("runtime_image") or ""
    return containers
