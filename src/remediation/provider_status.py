"""Read-only provider status polling for recovery requests."""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import quote
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class ProviderStatus:
    state: str
    merged: bool
    detail: dict


def fetch_provider_status(*, provider: str, repository: str, number: int, token: str, transport=urlopen) -> ProviderStatus:
    if number is None or number < 1:
        raise ValueError("provider number must be positive")
    if provider == "github":
        url = f"https://api.github.com/repos/{repository}/pulls/{number}"
        headers = {"Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}"}
    elif provider == "gitlab":
        url = f"https://gitlab.com/api/v4/projects/{quote(repository, safe='')}/merge_requests/{number}"
        headers = {"Accept": "application/json", "PRIVATE-TOKEN": token}
    else:
        raise ValueError("unsupported provider")
    response = transport(Request(url, headers=headers), timeout=10)
    payload = json.loads(response.read().decode())
    if provider == "github":
        merged = bool(payload.get("merged_at"))
        state = "merged" if merged else str(payload.get("state") or "unknown")
    else:
        state = str(payload.get("state") or "unknown")
        merged = state == "merged"
    return ProviderStatus(state=state, merged=merged, detail={"provider": provider, "state": state, "merged": merged})
