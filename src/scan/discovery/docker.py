"""List running Docker containers through the docker CLI."""

from __future__ import annotations

import json
from typing import Any

from src.scan.discovery._process import RuntimeUnavailable, failure, run_cli

# Only these fields leave `docker inspect`: never the environment, mounts or command.
INSPECT_FIELDS = ("Id", "Name", "Config.Image", "Image", "State.StartedAt")
INSPECT_FORMAT = "\t".join("{{json .%s}}" % field for field in INSPECT_FIELDS)


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

    async def inspect_containers(self, container_ids: list[str]) -> list[dict[str, str]] | None:
        """The INSPECT_FIELDS of each container still there, or None if Docker couldn't be asked.

        A container that stopped since it was listed is left out; `docker inspect` still prints the others.
        """
        if not container_ids:
            return []
        result = await run_cli([self.docker_bin, "container", "inspect", "--format", INSPECT_FORMAT, *container_ids])
        if result is None:
            return None
        found = []
        for line in result[1].splitlines():
            values = line.split("\t")
            if len(values) != len(INSPECT_FIELDS):
                continue
            try:
                decoded = [json.loads(value) for value in values]
            except json.JSONDecodeError:
                continue
            found.append({field: str(value or "") for field, value in zip(INSPECT_FIELDS, decoded)})
        if not found and result[0] != 0:
            return None
        return found
