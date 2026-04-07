"""Docker runtime collector — discovers containers and gathers runtime metrics.

Collects container resource utilisation (CPU, memory, network, disk I/O)
via ``docker stats`` and container metadata via ``docker inspect``.
Feeds the analysis engine with structured snapshots.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Any

from src.runtime.ebpf_agent import RuntimeEvent

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ContainerSnapshot:
    """A point-in-time resource snapshot for a container."""
    container_id: str
    cpu_percent: float = 0.0
    mem_usage_mb: float = 0.0
    mem_limit_mb: float = 0.0
    mem_percent: float = 0.0
    net_rx_bytes: int = 0
    net_tx_bytes: int = 0
    block_read_bytes: int = 0
    block_write_bytes: int = 0
    pids: int = 0
    image_name: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    def to_resource_event(self) -> RuntimeEvent:
        return RuntimeEvent(
            event_type="resource",
            container_id=self.container_id,
            image_name=self.image_name or None,
            detail={
                "cpu_pct": self.cpu_percent,
                "mem_mb": self.mem_usage_mb,
                "mem_limit_mb": self.mem_limit_mb,
                "mem_pct": self.mem_percent,
                "net_rx_bytes": self.net_rx_bytes,
                "net_tx_bytes": self.net_tx_bytes,
                "block_read": self.block_read_bytes,
                "block_write": self.block_write_bytes,
                "pids": self.pids,
            },
        )


def _parse_docker_stats(line: str) -> dict[str, Any] | None:
    """Parse a single line of ``docker stats --format json`` output."""
    try:
        return json.loads(line)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def _parse_size(val: str) -> float:
    """Convert a Docker size string like '123.4MiB' to bytes."""
    val = val.strip()
    multipliers = {
        "B": 1, "KiB": 1024, "MiB": 1024 ** 2, "GiB": 1024 ** 3,
        "kB": 1000, "MB": 1000 ** 2, "GB": 1000 ** 3,
    }
    for suffix, mult in sorted(multipliers.items(),
                                key=lambda x: -len(x[0])):
        if val.endswith(suffix):
            num_str = val[:-len(suffix)].strip()
            try:
                return float(num_str) * mult
            except ValueError:
                return 0.0
    try:
        return float(val)
    except ValueError:
        return 0.0


def _parse_pct(val: str) -> float:
    try:
        return float(val.rstrip("%"))
    except (ValueError, AttributeError):
        return 0.0


class DockerRuntimeCollector:
    """Collects container metadata and resource snapshots.

    Usage:
        collector = DockerRuntimeCollector()
        containers = await collector.list_running_containers()
        snapshot = await collector.collect_snapshot(container_id)
    """

    def __init__(self, docker_bin: str = "docker"):
        self.docker_bin = docker_bin

    async def list_running_containers(self) -> list[dict[str, Any]]:
        """Return a list of running containers with image and name."""
        cmd = [
            self.docker_bin, "ps", "--format", "json",
            "--no-trunc",
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=15)
        except (asyncio.TimeoutError, FileNotFoundError):
            return []

        containers: list[dict[str, Any]] = []
        for line in stdout.decode().splitlines():
            try:
                c = json.loads(line)
            except json.JSONDecodeError:
                continue
            containers.append({
                "id": c.get("ID", ""),
                "names": c.get("Names", ""),
                "image": c.get("Image", ""),
                "status": c.get("State", ""),
                "created": c.get("CreatedAt", ""),
                "ports": c.get("Ports", ""),
                "labels": c.get("Labels", {}),
            })
        return containers

    async def collect_snapshot(self, container_id: str) -> ContainerSnapshot | None:
        """Collect a single resource snapshot via ``docker stats --no-stream``."""
        cmd = [
            self.docker_bin, "stats", "--no-stream", "--format",
            "json", container_id,
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=15)
        except (asyncio.TimeoutError, FileNotFoundError) as e:
            logger.warning("docker stats failed for %s: %s", container_id, e)
            return None

        if proc.returncode != 0:
            # Container may have stopped
            return None

        parsed = _parse_docker_stats(stdout.decode().strip())
        if not parsed:
            return None

        mem_usage = _parse_size(parsed.get("MemUsage", "0")) / (1024 ** 2)
        mem_limit = _parse_size(parsed.get("MemLimit", "0")) / (1024 ** 2)

        net_io = parsed.get("NetIO", "0B / 0B").split("/")
        net_rx = _parse_size(net_io[0].strip()) if len(net_io) > 1 else 0
        net_tx = _parse_size(net_io[1].strip()) if len(net_io) > 1 else 0

        blk_io = parsed.get("BlockIO", "0B / 0B").split("/")
        blk_read = _parse_size(blk_io[0].strip()) if len(blk_io) > 1 else 0
        blk_write = _parse_size(blk_io[1].strip()) if len(blk_io) > 1 else 0

        return ContainerSnapshot(
            container_id=container_id,
            cpu_percent=_parse_pct(parsed.get("CPUPerc", "0")),
            mem_usage_mb=mem_usage,
            mem_limit_mb=mem_limit,
            mem_percent=_parse_pct(parsed.get("MemPerc", "0")),
            net_rx_bytes=int(net_rx),
            net_tx_bytes=int(net_tx),
            block_read_bytes=int(blk_read),
            block_write_bytes=int(blk_write),
            pids=int(parsed.get("PIDs", 0)),
            image_name=parsed.get("Name", ""),
            raw=parsed,
        )
