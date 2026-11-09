"""Minimal durable runtime-event sink for degraded and replay workflows."""

from __future__ import annotations

import json
import os
from pathlib import Path

from .ebpf_agent import RuntimeEvent


class JsonlEventStore:
    """Append-only JSONL store with fsync for each event."""

    def __init__(self, path: str | Path, max_bytes: int = 50_000_000, max_rotations: int = 1):
        self.path = Path(path)
        if max_bytes < 1:
            raise ValueError("max_bytes must be positive")
        if max_rotations < 1: raise ValueError("max_rotations must be positive")
        self.max_bytes = max_bytes
        self.max_rotations = max_rotations
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event: RuntimeEvent) -> None:
        if self.path.exists() and self.path.stat().st_size >= self.max_bytes:
            for index in range(self.max_rotations, 0, -1):
                source = self.path if index == 1 else self.path.with_suffix(self.path.suffix + f".{index - 1}")
                target = self.path.with_suffix(self.path.suffix + f".{index}")
                if source.exists(): source.replace(target)
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event.to_dict(), sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())

    def read(self, limit: int = 100, container_id: str | None = None) -> list[dict]:
        if limit < 1 or not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()
        events = []
        for line in lines:
            if not line: continue
            try: events.append(json.loads(line))
            except json.JSONDecodeError: continue
        if container_id is not None:
            events = [event for event in events if event.get("container_id") == container_id]
        return events[-limit:]
