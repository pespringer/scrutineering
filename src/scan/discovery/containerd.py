"""List running containerd containers through the ctr CLI."""

from __future__ import annotations

import logging
from typing import Any

from src.scan.discovery._process import run_cli

logger = logging.getLogger(__name__)


class ContainerdCollector:
    def __init__(self, ctr_bin: str = "ctr", namespace: str = "default"):
        self.ctr_bin = ctr_bin
        self.namespace = namespace

    def _ctr(self, *args: str) -> list[str]:
        return [self.ctr_bin, "-n", self.namespace, *args]

    async def list_running_containers(self) -> list[dict[str, Any]]:
        """Return container IDs in the namespace; image names come from get_container_info."""
        result = await run_cli(self._ctr("containers", "list", "-q"))
        if result is None:
            return []
        returncode, stdout, stderr = result
        if returncode != 0:
            logger.warning("ctr containers list failed: %s", stderr.strip())
            return []
        return [{"id": line.strip(), "namespace": self.namespace} for line in stdout.splitlines() if line.strip()]

    async def get_container_info(self, container_id: str) -> dict[str, Any] | None:
        """Return key/value pairs from `ctr containers info`, or None on failure."""
        result = await run_cli(self._ctr("containers", "info", container_id))
        if result is None or result[0] != 0:
            return None
        info: dict[str, Any] = {"id": container_id, "namespace": self.namespace}
        for line in result[1].strip().splitlines():
            key, sep, value = line.strip().partition(":")
            if sep:
                info[key.strip().lower().replace(" ", "_")] = value.strip()
        return info
