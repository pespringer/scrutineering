"""Content-addressed, bounded-TTL scanner result cache."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any


class ScanCache:
    def __init__(self, directory: str | Path, ttl_seconds: int = 3600):
        if ttl_seconds < 1:
            raise ValueError("ttl_seconds must be positive")
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.ttl_seconds = ttl_seconds

    def _path(self, scanner: str, image: str) -> Path:
        key = hashlib.sha256(f"{scanner}\0{image}".encode()).hexdigest()
        return self.directory / f"{key}.json"

    def get(self, scanner: str, image: str, now: float | None = None) -> list[dict[str, Any]] | None:
        path = self._path(scanner, image)
        try:
            payload = json.loads(path.read_text())
            current = time.time() if now is None else now
            if current - payload["created_at"] > self.ttl_seconds:
                path.unlink(missing_ok=True)
                return None
            return payload["findings"]
        except (FileNotFoundError, KeyError, json.JSONDecodeError, TypeError):
            return None

    def set(self, scanner: str, image: str, findings: list[dict[str, Any]], now: float | None = None) -> None:
        payload = {"created_at": time.time() if now is None else now, "findings": findings}
        fd, temporary = tempfile.mkstemp(prefix="scan-cache-", dir=self.directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(payload, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self._path(scanner, image))
        finally:
            Path(temporary).unlink(missing_ok=True)
