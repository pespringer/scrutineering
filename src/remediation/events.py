from __future__ import annotations

from datetime import datetime, timezone
import json

_SECRET_KEYS = {"token", "password", "secret", "authorization"}


def redact_detail(detail: dict) -> dict:
    return {key: ("[redacted]" if key.lower() in _SECRET_KEYS else value) for key, value in detail.items()}


def make_event(remediation_id: int, event_type: str, detail: dict | None = None, sequence: int | None = None) -> dict:
    if remediation_id < 1 or not event_type or len(event_type) > 64: raise ValueError("invalid remediation event")
    if sequence is not None and sequence < 1: raise ValueError("event sequence must be positive")
    safe_detail = redact_detail(detail or {})
    if len(json.dumps(safe_detail, sort_keys=True).encode()) > 100_000: raise ValueError("event detail exceeds size limit")
    return {"remediation_id": remediation_id, "event_type": event_type, "sequence": sequence, "detail": safe_detail, "created_at": datetime.now(timezone.utc).isoformat()}
