"""The scanner settings the worker applies, taken from `src/config.py`."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from src.config import get_settings


@dataclass(frozen=True)
class ScannerSettings:
    timeout_seconds: int = 600
    max_output_bytes: int = 50_000_000
    max_findings: int = 100_000
    retry_attempts: int = 2
    retry_backoff_seconds: float = 5.0
    trivy_cache_dir: str = "/tmp/trivy-cache"
    require_immutable_identity: bool = False
    registry_insecure: bool = False
    local_registry_host: str = "registry:5000"

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "ScannerSettings":
        settings = get_settings(env)
        return cls(
            timeout_seconds=settings.scanner_timeout,
            max_output_bytes=settings.scanner_max_output_bytes,
            max_findings=settings.scanner_max_findings,
            retry_attempts=settings.scanner_retry_attempts,
            retry_backoff_seconds=settings.scanner_retry_backoff_seconds,
            trivy_cache_dir=settings.scanner_cache_dir,
            require_immutable_identity=settings.require_immutable_scan_identity,
            registry_insecure=settings.registry_insecure,
            local_registry_host=settings.local_registry_host,
        )

    def insecure_host(self, host: str) -> bool:
        """Plain HTTP is allowed only for the local registry, and only when REGISTRY_INSECURE is set."""
        return self.registry_insecure and (host == self.local_registry_host or host.split(":")[0] == "localhost")
