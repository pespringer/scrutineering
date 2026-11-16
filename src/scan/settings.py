"""Scanner settings, read from the environment in one place.

Every setting listed here is applied by the worker; an invalid value fails
loudly instead of silently falling back to a default.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping


def _int(env: Mapping[str, str], name: str, default: int, *, minimum: int) -> int:
    raw = str(env.get(name, "")).strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from exc
    if value < minimum:
        raise ValueError(f"{name} must be at least {minimum}, got {value}")
    return value


def _float(env: Mapping[str, str], name: str, default: float, *, minimum: float) -> float:
    raw = str(env.get(name, "")).strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number, got {raw!r}") from exc
    if value < minimum:
        raise ValueError(f"{name} must be at least {minimum}, got {value}")
    return value


def _flag(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = str(env.get(name, "")).strip().lower()
    if not raw:
        return default
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be true or false, got {raw!r}")


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
        env = os.environ if env is None else env
        return cls(
            timeout_seconds=_int(env, "SCANNER_TIMEOUT", cls.timeout_seconds, minimum=1),
            max_output_bytes=_int(env, "SCANNER_MAX_OUTPUT_BYTES", cls.max_output_bytes, minimum=1),
            max_findings=_int(env, "SCANNER_MAX_FINDINGS", cls.max_findings, minimum=1),
            retry_attempts=_int(env, "SCANNER_RETRY_ATTEMPTS", cls.retry_attempts, minimum=0),
            retry_backoff_seconds=_float(env, "SCANNER_RETRY_BACKOFF_SECONDS", cls.retry_backoff_seconds, minimum=0),
            trivy_cache_dir=str(env.get("SCANNER_CACHE_DIR", "")).strip() or cls.trivy_cache_dir,
            require_immutable_identity=_flag(env, "REQUIRE_IMMUTABLE_SCAN_IDENTITY", cls.require_immutable_identity),
            registry_insecure=_flag(env, "REGISTRY_INSECURE", cls.registry_insecure),
            local_registry_host=str(env.get("LOCAL_REGISTRY_HOST", "")).strip() or cls.local_registry_host,
        )

    def insecure_host(self, host: str) -> bool:
        """Plain HTTP is allowed only for the local registry, and only when REGISTRY_INSECURE is set."""
        return self.registry_insecure and (host == self.local_registry_host or host.split(":")[0] == "localhost")
