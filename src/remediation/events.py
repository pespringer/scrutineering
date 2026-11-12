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


def publication_event_exists(events, *, event_type: str, publication_id: int, detail: dict) -> bool:
    """Return whether a post-merge event was already recorded for a publication."""
    for event in events:
        if event.event_type != event_type:
            continue
        event_detail = event.detail or {}
        if event_detail.get("publication_id") == publication_id:
            return True
        # Events written before publication IDs were included can still be
        # recognized by their deterministic verification result.
        if "publication_id" not in event_detail and event_detail == detail:
            return True
    return False


def recovery_request_exists(events, *, publication_id: int, idempotency_key: str):
    """Return a prior recovery request matching the operator idempotency key."""
    for event in events:
        if event.event_type != "publication_recovery_requested":
            continue
        detail = event.detail or {}
        if detail.get("publication_id") == publication_id and detail.get("idempotency_key") == idempotency_key:
            return detail
    return None
