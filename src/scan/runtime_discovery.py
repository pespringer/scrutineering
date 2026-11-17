"""Runtime container discovery helpers for scan scheduling."""

from __future__ import annotations

import fnmatch
from typing import Any


def _labels_match(labels: Any, expression: str | None) -> bool:
    if not expression:
        return True
    key, separator, expected = expression.partition("=")
    if not separator or not key:
        return False
    if isinstance(labels, str):
        labels = dict(item.split("=", 1) for item in labels.split(",") if "=" in item)
    return isinstance(labels, dict) and labels.get(key) == expected


def select_runtime_images(
    containers: list[dict[str, Any]],
    *,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    exclude_containers: list[str] | None = None,
    include_label: str | None = None,
    limit: int = 100,
) -> list[str]:
    """Return stable, unique image references selected from running containers."""
    if limit < 1:
        raise ValueError("runtime discovery limit must be positive")
    include, exclude, exclude_containers = include or [], exclude or [], exclude_containers or []
    selected: list[str] = []
    seen: set[str] = set()
    for container in containers:
        image = str(container.get("image") or "").strip()
        name = str(container.get("names") or container.get("id") or "").strip()
        if not image or not _labels_match(container.get("labels"), include_label):
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


async def discover_runtime_containers(
    *,
    use_containerd: bool = False,
    docker_bin: str = "docker",
    ctr_bin: str = "ctr",
    containerd_namespace: str = "default",
) -> list[dict[str, Any]]:
    """Discover containers and enrich containerd records with image names."""
    if use_containerd:
        from src.scan.discovery import ContainerdCollector

        collector = ContainerdCollector(ctr_bin=ctr_bin, namespace=containerd_namespace)
    else:
        from src.scan.discovery import DockerRuntimeCollector

        collector = DockerRuntimeCollector(docker_bin=docker_bin)
    containers = await collector.list_running_containers()
    if use_containerd:
        for container in containers:
            if not container.get("image"):
                info = await collector.get_container_info(container["id"])
                if info:
                    container["image"] = info.get("image") or info.get("runtime_image") or ""
    return containers
