"""Versioned alert payload contract and adapter boundary."""

from __future__ import annotations

from typing import Protocol


class AlertAdapter(Protocol):
    def deliver(self, payload: dict) -> tuple[int, str]: ...


REQUIRED_FIELDS = {"event_type", "publication_id"}


def validate_alert_payload(payload: dict) -> dict:
    if not isinstance(payload, dict) or not REQUIRED_FIELDS <= payload.keys():
        raise ValueError("alert payload requires event_type and publication_id")
    if not isinstance(payload["event_type"], str) or not payload["event_type"].strip():
        raise ValueError("alert event_type must be non-empty")
    if not isinstance(payload["publication_id"], int) or payload["publication_id"] < 1:
        raise ValueError("alert publication_id must be positive")
    return {"schema_version": "alert-v1", **payload}
