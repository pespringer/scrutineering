"""HMAC authentication for internal service-to-service requests."""

from __future__ import annotations

import hashlib
import hmac
import time


def sign_service_request(service: str, body: bytes, secret: str, timestamp: int | None = None) -> dict[str, str]:
    issued = str(timestamp or int(time.time()))
    message = f"{service}:{issued}:".encode() + body
    signature = hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()
    return {"x-service-name": service, "x-service-timestamp": issued, "x-service-signature": signature}


def verify_service_request(headers: dict[str, str], body: bytes, secret: str, *, max_skew_seconds: int = 300, now: int | None = None) -> bool:
    service = headers.get("x-service-name", "")
    issued = headers.get("x-service-timestamp", "")
    signature = headers.get("x-service-signature", "")
    try:
        if abs((now or int(time.time())) - int(issued)) > max_skew_seconds: return False
    except ValueError:
        return False
    expected = sign_service_request(service, body, secret, int(issued))["x-service-signature"]
    return bool(service and signature) and hmac.compare_digest(signature, expected)


def create_replay_guard(max_entries: int = 10_000):
    if max_entries < 1: raise ValueError("max_entries must be positive")
    seen: dict[str, int] = {}
    def check(signature: str, now: int) -> bool:
        for key, expires in list(seen.items()):
            if expires < now: seen.pop(key, None)
        if signature in seen: return False
        if len(seen) >= max_entries: return False
        seen[signature] = now + 300
        return True
    return check
