"""Portable evidence archive manifests with integrity verification."""

from __future__ import annotations

import hashlib
import json
import gzip


def manifest(records: list[dict], *, source: str = "dashboard-export", key_id: str | None = None) -> dict:
    canonical = json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
    return {"format": "scrutineering-evidence-archive-v1", "source": source, "count": len(records), "sha256": hashlib.sha256(canonical).hexdigest(), "key_id": key_id, "records": records}


def compress_manifest(value: dict) -> bytes:
    return gzip.compress(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def decompress_manifest(value: bytes) -> dict:
    return json.loads(gzip.decompress(value).decode())


def verify_manifest(value: dict) -> bool:
    records = value.get("records")
    if not isinstance(records, list) or value.get("format") != "scrutineering-evidence-archive-v1":
        return False
    canonical = json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
    return value.get("count") == len(records) and value.get("sha256") == hashlib.sha256(canonical).hexdigest()
