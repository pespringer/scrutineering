"""Provider credential rotation diagnostics without exposing token material."""

from __future__ import annotations

import os
from datetime import datetime, timezone


def credential_diagnostics(provider: str) -> dict:
    name = "GITHUB_TOKEN" if provider == "github" else "GITLAB_TOKEN"
    token = os.environ.get(name, "")
    rotated_at = os.environ.get(f"{name}_ROTATED_AT", "")
    age_days = None
    if rotated_at:
        try:
            timestamp = datetime.fromisoformat(rotated_at.replace("Z", "+00:00"))
            age_days = max(0, (datetime.now(timezone.utc) - timestamp).days)
        except ValueError:
            return {"provider": provider, "configured": bool(token), "rotation_metadata_valid": False, "age_days": None}
    max_age = int(os.environ.get("PROVIDER_TOKEN_MAX_AGE_DAYS", "90"))
    required_scopes = [scope for scope in os.environ.get(f"{name}_REQUIRED_SCOPES", "").split(",") if scope]
    return {"provider": provider, "configured": bool(token), "rotation_metadata_valid": True, "age_days": age_days, "rotation_stale": age_days is not None and age_days > max_age, "max_age_days": max_age, "token_present": bool(token), "required_scopes": required_scopes, "scope_metadata_valid": all(scope.replace("_", "").replace(":", "").isalnum() for scope in required_scopes)}
