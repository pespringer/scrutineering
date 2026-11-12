"""Streaming-friendly audit export serialization."""

from __future__ import annotations

import json
from collections.abc import Iterable


def iter_jsonl(records: Iterable[dict]):
    for record in records:
        yield json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"


def verify_chain(records: list[dict]) -> bool:
    previous = None
    for record in records:
        if record.get("previous_hash") != previous:
            return False
        previous = record.get("record_hash")
    return True
