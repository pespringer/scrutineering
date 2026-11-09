from __future__ import annotations

from datetime import datetime, timezone


def make_event(remediation_id: int, event_type: str, detail: dict | None = None) -> dict:
    if remediation_id < 1 or not event_type or len(event_type) > 64: raise ValueError("invalid remediation event")
    return {"remediation_id": remediation_id, "event_type": event_type, "detail": detail or {}, "created_at": datetime.now(timezone.utc).isoformat()}
