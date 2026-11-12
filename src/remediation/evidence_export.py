"""Canonical, optionally signed release-evidence export envelopes."""

from __future__ import annotations

import hashlib
import hmac
import json


def canonical_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def sign_export(payload: dict, secret: str) -> dict:
    if not secret:
        raise ValueError("evidence export signing secret is required")
    body = canonical_bytes(payload)
    return {"algorithm": "HMAC-SHA256", "sha256": hashlib.sha256(body).hexdigest(), "signature": hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()}


def verify_export(payload: dict, envelope: dict, secret: str) -> bool:
    if envelope.get("algorithm") != "HMAC-SHA256" or envelope.get("sha256") != hashlib.sha256(canonical_bytes(payload)).hexdigest():
        return False
    return bool(secret) and hmac.compare_digest(envelope.get("signature", ""), sign_export(payload, secret)["signature"])
