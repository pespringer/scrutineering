"""The generic webhook channel: signed JSON, for ntfy, n8n, Home Assistant or your own receiver."""

from __future__ import annotations

import hashlib
import hmac
import json

SIGNATURE_HEADER = "X-Scrutineering-Signature"
DELIVERY_HEADER = "X-Scrutineering-Delivery"
EVENT_HEADER = "X-Scrutineering-Event"


def body(notification_id: int, payload: dict) -> bytes:
    """The request body: the stored payload with the delivery ID, which receivers use to drop repeats."""
    return json.dumps({"id": notification_id, **payload}, sort_keys=True, separators=(",", ":")).encode()


def signature(secret: str, raw_body: bytes) -> str:
    """`sha256=<hex HMAC-SHA256 of the raw body>`, the same scheme as GitHub's webhooks."""
    return "sha256=" + hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()


def request(notification_id: int, event: str, payload: dict, secret: str) -> tuple[bytes, dict[str, str]]:
    raw = body(notification_id, payload)
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "scrutineering-notifications",
        SIGNATURE_HEADER: signature(secret, raw),
        DELIVERY_HEADER: str(notification_id),
        EVENT_HEADER: event,
    }
    return raw, headers
