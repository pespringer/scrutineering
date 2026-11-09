"""Minimal durable runtime-event sink for degraded and replay workflows."""

from __future__ import annotations

import json
import os
from pathlib import Path

from .ebpf_agent import RuntimeEvent


class JsonlEventStore:
    """Append-only JSONL store with fsync for each event."""

    def __init__(self, path: str | Path, max_bytes: int = 50_000_000):
        self.path = Path(path)
        if max_bytes < 1:
            raise ValueError("max_bytes must be positive")
        self.max_bytes = max_bytes
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event: RuntimeEvent) -> None:
        if self.path.exists() and self.path.stat().st_size >= self.max_bytes:
            rotated = self.path.with_suffix(self.path.suffix + ".1")
            rotated.unlink(missing_ok=True)
            self.path.replace(rotated)
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event.to_dict(), sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())

    def read(self, limit: int = 100, container_id: str | None = None) -> list[dict]:
        if limit < 1 or not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()
        events = [json.loads(line) for line in lines if line]
        if container_id is not None:
            events = [event for event in events if event.get("container_id") == container_id]
        return events[-limit:]
