from __future__ import annotations

from dataclasses import dataclass


@dataclass
class AuditAnchor:
    sink: object

    def publish(self, record_hash: str) -> str:
        if not record_hash or len(record_hash) != 71 or not record_hash.startswith("sha256:"): raise ValueError("audit hash must be sha256")
        result = self.sink(record_hash)
        if result is None or result == "": raise RuntimeError("audit anchor did not return an identifier")
        return str(result)
