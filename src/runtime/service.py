"""Unified runtime monitoring service.

Wires together the eBPF agent, Docker/containerd stats collectors,
behaviour analyzer, and alert manager into a single start/stop service.
Also persists events to PostgreSQL via the ContainerRuntime model.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Any, Callable

from src.runtime.ebpf_agent import EBPFMonitorAgent, RuntimeEvent
from src.runtime.analysis import RuntimeBehaviorAnalyzer, Anomaly
from src.runtime.docker_monitor import DockerRuntimeCollector
from src.runtime.containerd_monitor import ContainerdCollector
from src.runtime.alerts import AlertManager

logger = logging.getLogger(__name__)


class RuntimeMonitoringService:
    """Orchestrates runtime monitoring for all watched containers.

    Supports both Docker and containerd runtimes, chosen at
    initialisation time (``use_containerd=True`` for containerd).

    Usage::

        service = RuntimeMonitoringService()
        await service.start()
        # ... events flow through callbacks ...
        await service.stop()
    """

    def __init__(
        self,
        docker_bin: str = "docker",
        ctr_bin: str = "ctr",
        containerd_namespace: str = "default",
        use_containerd: bool = False,
        stats_interval: int = 30,  # seconds between resource snapshots
        min_alert_severity: str = "medium",
        alert_cooldown: int = 300,
        db_persist: bool = True,
        get_db_session: Callable | None = None,
        image_lookup: Callable[[str], int | None] | None = None,
    ):
        self.docker_bin = docker_bin
        self.stats_interval = stats_interval
        self.db_persist = db_persist
        self._get_session = get_db_session
        self._image_lookup = image_lookup  # container_id -> image_id
        self._use_containerd = use_containerd

        self.agent = EBPFMonitorAgent(docker_bin=docker_bin)
        self.analyzer = RuntimeBehaviorAnalyzer()
        self.alert_manager = AlertManager(
            min_alert_severity=min_alert_severity,
            cooldown_seconds=alert_cooldown,
        )

        # Select collector backend
        if use_containerd:
            self.collector: DockerRuntimeCollector | ContainerdCollector = (
                ContainerdCollector(ctr_bin=ctr_bin, namespace=containerd_namespace)
            )
        else:
            self.collector = DockerRuntimeCollector(docker_bin=docker_bin)

        # Wire analyzer -> alerts
        self.analyzer.set_anomaly_callback(
            self.alert_manager.anomaly_handler()
        )

        self._running = False
        self._stats_task: asyncio.Task | None = None
        self._watched_containers: set[str] = set()

    async def start(self) -> None:
        """Start the monitoring service and its periodic tasks."""
        self._running = True
        await self.agent.start()
        self._stats_task = asyncio.create_task(self._stats_loop())
        logger.info("Runtime monitoring service started")
        await self._discover_containers()

    async def stop(self) -> None:
        """Gracefully stop all monitoring."""
        self._running = False
        if self._stats_task:
            self._stats_task.cancel()
            try:
                await self._stats_task
            except asyncio.CancelledError:
                pass
        await self.agent.stop()
        logger.info("Runtime monitoring service stopped")

    # -- Container discovery ------------------------------------------------ #

    async def _discover_containers(self) -> None:
        """Auto-discover running containers via Docker or containerd."""
        try:
            containers = await self.collector.list_running_containers()
            new_ids = {c["id"] for c in containers}
            to_add = new_ids - self._watched_containers
            to_remove = self._watched_containers - new_ids

            for cid in to_add:
                self._watched_containers.add(cid)
                logger.info("Discovered new container: %s", cid)

            for cid in to_remove:
                self._watched_containers.discard(cid)
                self.analyzer.clear_baseline(cid)
                logger.info("Container stopped: %s", cid)

        except Exception:
            logger.exception("Container discovery failed")

    async def add_container(self, container_id: str) -> None:
        self._watched_containers.add(container_id)

    async def remove_container(self, container_id: str) -> None:
        self._watched_containers.discard(container_id)
        self.analyzer.clear_baseline(container_id)

    def get_watched(self) -> list[str]:
        return list(self._watched_containers)

    # -- Resource stats loop ------------------------------------------------ #

    async def _stats_loop(self) -> None:
        """Periodically collect resource snapshots for all containers."""
        while self._running:
            try:
                await self._discover_containers()
                for cid in list(self._watched_containers):
                    snapshot = await self.collector.collect_snapshot(cid)
                    if snapshot:
                        event = snapshot.to_resource_event()
                        if snapshot.image_name:
                            event.image_name = snapshot.image_name
                        self.analyzer.process_event(event)
                        if self.db_persist and self._get_session:
                            await self._persist_event(event)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Stats loop error")
            await asyncio.sleep(self.stats_interval)

    # -- Event ingestion from eBPF agent ------------------------------------ #

    async def handle_event(self, event: RuntimeEvent) -> None:
        """Called for each event from the eBPF/Docker/containerd backend."""
        self.analyzer.process_event(event)
        if self.db_persist and self._get_session:
            await self._persist_event(event)

    # -- DB persistence ----------------------------------------------------- #

    async def _persist_event(self, event: RuntimeEvent) -> None:
        """Persist a runtime event to the database."""
        if not self._get_session:
            return
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None, self._sync_persist_event, event
            )
        except Exception:
            # Don't let DB errors halt monitoring
            logger.exception("Failed to persist runtime event")

    def _sync_persist_event(self, event: RuntimeEvent) -> None:
        try:
            from src.db.connection import get_session
            from src.db.models import ContainerRuntime

            # Resolve image_id if we have a lookup function
            image_id: int | None = None
            if self._image_lookup is not None:
                try:
                    image_id = self._image_lookup(event.container_id)
                except Exception:
                    logger.debug(
                        "image_lookup failed for %s", event.container_id
                    )

            with get_session() as session:
                record = ContainerRuntime(
                    container_id=event.container_id,
                    image_id=image_id,
                    timestamp=datetime.fromtimestamp(
                        event.timestamp, tz=timezone.utc
                    ),
                    event_type=event.event_type,
                    severity=event.severity,
                    detail=event.detail,
                    source=event.source,
                )
                session.add(record)
        except Exception:
            logger.exception("DB persist error")

    # -- Dashboard data API ------------------------------------------------- #

    def get_anomalies(
        self,
        container_id: str | None = None,
        since: datetime | None = None,
        unresolved_only: bool = True,
    ) -> list[dict]:
        return self.analyzer.get_anomalies(
            container_id=container_id,
            since=since,
            unresolved_only=unresolved_only,
        )

    def get_alerts(
        self,
        container_id: str | None = None,
        severity: str | None = None,
        unresolved_only: bool = True,
        limit: int = 100,
    ) -> list[dict]:
        return self.alert_manager.list_alerts(
            container_id=container_id,
            severity=severity,
            unresolved_only=unresolved_only,
            limit=limit,
        )

    def get_resource_stats(self, container_id: str) -> dict:
        return self.analyzer.get_resource_stats(container_id)

    def get_overview(self) -> dict:
        return {
            "watched_containers": len(self._watched_containers),
            "containers": list(self._watched_containers),
            "alert_stats": self.alert_manager.stats(),
            "anomaly_count": len(
                self.analyzer.get_anomalies(unresolved_only=True)
            ),
        }
