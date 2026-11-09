from __future__ import annotations

import json
from pathlib import Path


class ReplayCheckpoint:
    def __init__(self, path: str | Path): self.path = Path(path)
    def load(self) -> int: 
        try: return int(json.loads(self.path.read_text())["offset"])
        except (FileNotFoundError, KeyError, ValueError, json.JSONDecodeError): return 0
    def save(self, offset: int) -> None:
        if offset < 0: raise ValueError("offset must be non-negative")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({"offset": offset}) + "\n")
