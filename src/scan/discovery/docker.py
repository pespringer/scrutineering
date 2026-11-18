"""List running Docker containers through the docker CLI."""

from __future__ import annotations

import json
from typing import Any

from src.scan.discovery._process import RuntimeUnavailable, failure, run_cli


class DockerRuntimeCollector:
    def __init__(self, docker_bin: str = "docker"):
        self.docker_bin = docker_bin

    async def list_running_containers(self) -> list[dict[str, Any]]:
        """Return running containers with their image, names, and labels; raise if Docker can't be reached."""
        result = await run_cli([self.docker_bin, "ps", "--format", "json", "--no-trunc"])
        problem = failure(result, self.docker_bin)
        if problem:
            raise RuntimeUnavailable(problem)
        _, stdout, _ = result
        containers: list[dict[str, Any]] = []
        for line in stdout.splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            containers.append(
                {
                    "id": record.get("ID", ""),
                    "names": record.get("Names", ""),
                    "image": record.get("Image", ""),
                    "status": record.get("State", ""),
                    "created": record.get("CreatedAt", ""),
                    "ports": record.get("Ports", ""),
                    "labels": record.get("Labels", {}),
                }
            )
        return containers

    async def repo_digests(self, image: str) -> list[str] | None:
        """The image's registry digests (`repo@sha256:...`); empty for an image built locally, None if unknown."""
        result = await run_cli([self.docker_bin, "image", "inspect", "--format", "{{json .RepoDigests}}", image])
        if failure(result, self.docker_bin):
            return None
        try:
            digests = json.loads(result[1].strip() or "null")
        except json.JSONDecodeError:
            return None
        return [str(item) for item in digests] if isinstance(digests, list) else []
