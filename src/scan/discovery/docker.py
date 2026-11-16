"""List running Docker containers through the docker CLI."""

from __future__ import annotations

import json
from typing import Any

from src.scan.discovery._process import run_cli


class DockerRuntimeCollector:
    def __init__(self, docker_bin: str = "docker"):
        self.docker_bin = docker_bin

    async def list_running_containers(self) -> list[dict[str, Any]]:
        """Return running containers with their image, names, and labels."""
        result = await run_cli([self.docker_bin, "ps", "--format", "json", "--no-trunc"])
        if result is None:
            return []
        _, stdout, _ = result
        containers: list[dict[str, Any]] = []
        for line in stdout.splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            containers.append({
                "id": record.get("ID", ""),
                "names": record.get("Names", ""),
                "image": record.get("Image", ""),
                "status": record.get("State", ""),
                "created": record.get("CreatedAt", ""),
                "ports": record.get("Ports", ""),
                "labels": record.get("Labels", {}),
            })
        return containers
