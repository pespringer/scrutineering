"""Short-lived, tamper-evident approval tokens for remediation writes."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import re


def approval_token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def issue_approval(remediation_id: str, approver: str, secret: str, *, ttl_seconds: int = 900, now: int | None = None) -> str:
    if not remediation_id or not re.fullmatch(r"[A-Za-z0-9._@:-]{1,128}", approver) or not secret or ttl_seconds < 1 or ttl_seconds > 86400:
        raise ValueError("approval fields and positive TTL are required")
    payload = {"remediation_id": remediation_id, "approver": approver, "expires_at": (now or int(time.time())) + ttl_seconds}
    encoded = base64.urlsafe_b64encode(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).decode().rstrip("=")
    signature = hmac.new(secret.encode(), encoded.encode(), hashlib.sha256).hexdigest()
    return f"{encoded}.{signature}"


def verify_approval(token: str, remediation_id: str, secret: str, *, now: int | None = None) -> dict:
    try:
        encoded, signature = token.split(".", 1)
        expected = hmac.new(secret.encode(), encoded.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError("invalid approval signature")
        payload = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("invalid approval token") from exc
    if payload.get("remediation_id") != remediation_id or payload.get("expires_at", 0) < (now or int(time.time())):
        raise ValueError("approval token is invalid or expired")
    return payload
