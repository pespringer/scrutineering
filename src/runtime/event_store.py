"""Minimal durable runtime-event sink for degraded and replay workflows."""

from __future__ import annotations

import json
import os
from pathlib import Path

from .ebpf_agent import RuntimeEvent


class JsonlEventStore:
    """Append-only JSONL store with fsync for each event."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event: RuntimeEvent) -> None:
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event.to_dict(), sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())

    def read(self, limit: int = 100) -> list[dict]:
        if limit < 1 or not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()
        return [json.loads(line) for line in lines[-limit:]]
