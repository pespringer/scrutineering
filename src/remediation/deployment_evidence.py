"""Authentication helpers for deployment evidence callbacks."""

from __future__ import annotations

import hashlib
import hmac


def verify_deployment_signature(*, body: bytes, signature: str, secret: str) -> bool:
    """Verify the exact request body with the deployment callback secret."""
    if not secret or not signature.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, expected)
