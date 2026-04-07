"""containerd runtime collector — discovers containers and gathers metrics.

Connects to containerd via ``ctr`` CLI (or the Python client if available)
to list running containers and collect resource snapshots.
Provides the same interface as DockerRuntimeCollector so the service
can use either backend transparently.
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
class ContainerdSnapshot:
    """A point-in-time resource snapshot for a containerd container."""
    container_id: str
    namespace: str = "default"
    cpu_percent: float = 0.0
    mem_usage_mb: float = 0.0
    mem_limit_mb: float = 0.0
    pid: int = 0
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
                "namespace": self.namespace,
                "pid": self.pid,
            },
        )


class ContainerdCollector:
    """Collects containerd container metadata and resource snapshots.

    Uses ``ctr`` CLI (included with containerd) for compatibility
    without requiring the Python containerd client library.

    Usage:
        collector = ContainerdCollector()
        containers = await collector.list_running_containers()
        snapshot = await collector.collect_snapshot(container_id)
    """

    def __init__(self, ctr_bin: str = "ctr", namespace: str = "default"):
        self.ctr_bin = ctr_bin
        self.namespace = namespace

    def _ctr(self, *args: str) -> list[str]:
        """Build a ctr command line with namespace prefix."""
        return [self.ctr_bin, "-n", self.namespace, *args]

    async def list_running_containers(self) -> list[dict[str, Any]]:
        """Return a list of running containers in the namespace."""
        cmd = self._ctr("containers", "list", "-q")
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=15)
        except (asyncio.TimeoutError, FileNotFoundError):
            return []

        if proc.returncode != 0:
            err = stderr.decode().strip()
            logger.warning("ctr containers list failed: %s", err)
            return []

        containers: list[dict[str, Any]] = []
        for line in stdout.decode().splitlines():
            cid = line.strip()
            if not cid:
                continue
            containers.append({
                "id": cid,
                "namespace": self.namespace,
            })
        return containers

    async def get_container_info(self, container_id: str) -> dict[str, Any] | None:
        """Get detailed container info via ``ctr containers info``."""
        cmd = self._ctr("containers", "info", container_id)
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=15)
        except (asyncio.TimeoutError, FileNotFoundError):
            return None

        if proc.returncode != 0:
            return None

        output = stdout.decode().strip()
        # ctr containers info outputs a table, not JSON
        # Parse key-value pairs
        info: dict[str, Any] = {"id": container_id, "namespace": self.namespace}
        for line in output.splitlines():
            line = line.strip()
            if ":" in line:
                key, _, value = line.partition(":")
                info[key.strip().lower().replace(" ", "_")] = value.strip()
        return info

    async def collect_snapshot(self, container_id: str) -> ContainerdSnapshot | None:
        """Collect a resource snapshot for a containerd container.

        containerd doesn't have a built-in ``stats`` command like Docker,
        so we use ``ctr task metrics`` which outputs cgroup metrics.
        """
        cmd = self._ctr("task", "metrics", container_id)
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=15)
        except (asyncio.TimeoutError, FileNotFoundError) as e:
            logger.warning("ctr task metrics failed for %s: %s",
                           container_id, e)
            return None

        if proc.returncode != 0:
            return None

        # Parse the metrics output (tab-separated)
        # Format: ID  VALUE  UNIT
        cpu_pct = 0.0
        mem_mb = 0.0
        mem_limit = 0.0
        pid_count = 0

        for line in stdout.decode().splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            metric_name = parts[0].lower()
            try:
                value = float(parts[1])
            except ValueError:
                continue
            unit = parts[2] if len(parts) > 2 else ""

            if "cpu" in metric_name and "%" in unit:
                cpu_pct = value
            elif "memory" in metric_name and "usage" in metric_name:
                if "MB" in unit or "MiB" in unit:
                    mem_mb = value
                elif "GB" in unit or "GiB" in unit:
                    mem_mb = value * 1024
                elif "KB" in unit or "KiB" in unit:
                    mem_mb = value / 1024
                elif "B" in unit:
                    mem_mb = value / (1024 ** 2)
            elif "memory" in metric_name and "limit" in metric_name:
                if "MB" in unit or "MiB" in unit:
                    mem_limit = value
                elif "GB" in unit or "GiB" in unit:
                    mem_limit = value * 1024
                elif "B" in unit:
                    mem_limit = value / (1024 ** 2)
            elif "pids" in metric_name:
                pid_count = int(value)

        # Also get image info
        container_info = await self.get_container_info(container_id)
        image_name = ""
        if container_info:
            image_name = container_info.get("image", "")

        return ContainerdSnapshot(
            container_id=container_id,
            namespace=self.namespace,
            cpu_percent=cpu_pct,
            mem_usage_mb=mem_mb,
            mem_limit_mb=mem_limit,
            pid=pid_count,
            image_name=image_name,
            raw={"container_info": container_info},
        )

    async def watch_events(self) -> asyncio.Queue[dict]:
        """Stream containerd events for lifecycle monitoring.

        Uses ``ctr events`` to watch for container start/stop/oom events.
        Returns an async queue of event dicts.
        """
        queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=1000)
        cmd = self._ctr("events", "stream")

        async def _reader() -> None:
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                assert proc.stdout is not None
                async for line in proc.stdout:
                    payload = line.decode().strip()
                    if not payload:
                        continue
                    try:
                        evt = json.loads(payload)
                        await queue.put(evt)
                    except json.JSONDecodeError:
                        # ctr events are tab-separated: timestamp topic data
                        parts = payload.split("\t", 2)
                        if len(parts) >= 3:
                            await queue.put({
                                "timestamp": parts[0],
                                "topic": parts[1],
                                "data": parts[2],
                            })
            except asyncio.CancelledError:
                pass
            except Exception as exc:
                logger.error("containerd event stream error: %s", exc)

        task = asyncio.create_task(_reader())
        return queue, task
