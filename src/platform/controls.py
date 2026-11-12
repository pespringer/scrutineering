"""Small, deterministic controls for lifecycle, execution, provider, and DR safety."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable


@dataclass(frozen=True)
class RetentionPolicy:
    days: int = 365
    purge_enabled: bool = False
    dry_run: bool = True

    def cutoff(self, now: datetime | None = None) -> datetime:
        if self.days < 1:
            raise ValueError("retention days must be positive")
        current = now or datetime.now(timezone.utc)
        return current - timedelta(days=self.days)

    def can_purge(self) -> bool:
        return self.purge_enabled and not self.dry_run


def page_bounds(limit: int, offset: int, *, maximum: int = 100) -> tuple[int, int]:
    if not 1 <= limit <= maximum or offset < 0:
        raise ValueError("invalid page bounds")
    return limit, offset


def bounded_output(value: str, maximum: int = 2000) -> str:
    if maximum < 1:
        raise ValueError("output limit must be positive")
    return value[-maximum:]


_SAFE_PATH = re.compile(r"^[A-Za-z0-9._/-]+$")


def guard_changed_files(paths: Iterable[str], *, maximum: int = 50) -> list[str]:
    values = sorted(set(paths))
    if len(values) > maximum:
        raise ValueError("changed-file limit exceeded")
    if any(not path or path.startswith("/") or ".." in path.split("/") or not _SAFE_PATH.match(path) for path in values):
        raise ValueError("unsafe changed file")
    return values


def classify_validation_failure(returncode: int, stderr: str = "") -> str:
    if returncode == 0:
        return "success"
    if "timed out" in stderr.lower() or "timeout" in stderr.lower():
        return "timeout"
    if returncode in {126, 127}:
        return "environment"
    return "validation_failed"


@dataclass(frozen=True)
class RetryPolicy:
    maximum_attempts: int = 5
    base_seconds: int = 15
    maximum_seconds: int = 300

    def delay(self, attempt: int) -> int:
        if attempt < 1 or self.maximum_attempts < 1:
            raise ValueError("invalid retry attempt")
        return min(self.maximum_seconds, self.base_seconds * (2 ** (attempt - 1)))

    def terminal(self, attempt: int) -> bool:
        return attempt >= self.maximum_attempts


@dataclass(frozen=True)
class ProviderPage:
    items: tuple[dict, ...]
    next_cursor: str | None = None

    def bounded(self, maximum: int = 100) -> "ProviderPage":
        if len(self.items) > maximum:
            raise ValueError("provider page exceeds maximum")
        return self


def parse_retry_after(value: str | None, *, default: int = 60, maximum: int = 900) -> int:
    try:
        parsed = int(value or default)
    except ValueError:
        parsed = default
    return max(0, min(parsed, maximum))


def backup_manifest(records: list[dict], *, source: str) -> dict:
    canonical = json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
    return {"format": "scrutineering-backup-v1", "source": source, "count": len(records), "sha256": hashlib.sha256(canonical).hexdigest()}


def verify_backup(records: list[dict], value: dict) -> bool:
    return value == backup_manifest(records, source=value.get("source", ""))


@dataclass(frozen=True)
class QueueHealth:
    depth: int
    oldest_age_seconds: int
    starvation_seconds: int = 900

    def status(self) -> str:
        if self.depth < 0 or self.oldest_age_seconds < 0:
            raise ValueError("queue metrics must not be negative")
        return "starved" if self.depth and self.oldest_age_seconds >= self.starvation_seconds else "healthy"
