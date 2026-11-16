"""Bounds and classifications applied while executing and publishing remediations."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable

_SAFE_PATH = re.compile(r"^[A-Za-z0-9._/-]+$")


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


def bounded_output(value: str, maximum: int = 2000) -> str:
    """Keep the last `maximum` characters of command output."""
    if maximum < 1:
        raise ValueError("output limit must be positive")
    return value[-maximum:]


def guard_changed_files(paths: Iterable[str], *, maximum: int = 50) -> list[str]:
    """Reject too many changed files, absolute paths, traversal, and unusual characters."""
    values = sorted(set(paths))
    if len(values) > maximum:
        raise ValueError("changed-file limit exceeded")
    for path in values:
        if not path or path.startswith("/") or ".." in path.split("/") or not _SAFE_PATH.match(path):
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


def parse_retry_after(value: str | None, *, default: int = 60, maximum: int = 900) -> int:
    """Parse a provider Retry-After header in seconds, clamped to [0, maximum]."""
    try:
        parsed = int(value or default)
    except ValueError:
        parsed = default
    return max(0, min(parsed, maximum))
