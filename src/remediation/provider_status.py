"""Read-only provider status polling for recovery requests."""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from threading import Lock
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class ProviderStatus:
    state: str
    merged: bool
    detail: dict


class ProviderRateLimited(RuntimeError):
    """Provider requested a retry, optionally after a server-provided delay."""
    def __init__(self, retry_after: int | None, detail: str):
        super().__init__(detail)
        self.retry_after = retry_after


class ProviderCircuitOpen(RuntimeError):
    pass


def validate_status_payload(provider: str, payload: dict) -> None:
    if not isinstance(payload, dict):
        raise ValueError("provider response must be an object")
    state = payload.get("state")
    allowed = {"open", "closed", "merged", "opened", "locked", "reopened", "unknown"}
    if state is not None and state not in allowed:
        raise ValueError("provider response contains an unsupported state")
    if provider == "github" and payload.get("merged_at") is not None and not isinstance(payload.get("merged_at"), str):
        raise ValueError("github merged_at must be a timestamp string")


class ProviderCircuitBreaker:
    """Small process-local breaker preventing repeated provider failures."""
    def __init__(self, *, threshold: int = 3, cooldown_seconds: int = 60):
        self.threshold = threshold
        self.cooldown_seconds = cooldown_seconds
        self._failures = 0
        self._opened_at = 0.0
        self._lock = Lock()

    def before_call(self) -> None:
        with self._lock:
            if self._opened_at and time.monotonic() - self._opened_at < self.cooldown_seconds:
                raise ProviderCircuitOpen("provider circuit is open")

    def success(self) -> None:
        with self._lock:
            self._failures = 0
            self._opened_at = 0.0

    def failure(self) -> None:
        with self._lock:
            self._failures += 1
            if self._failures >= self.threshold:
                self._opened_at = time.monotonic()


_BREAKERS: dict[str, ProviderCircuitBreaker] = {}
_STATUS_CACHE: dict[tuple[str, str, int], tuple[float, ProviderStatus]] = {}


def breaker_for(provider: str) -> ProviderCircuitBreaker:
    return _BREAKERS.setdefault(provider, ProviderCircuitBreaker())


def fetch_provider_status(*, provider: str, repository: str, number: int, token: str, transport=urlopen) -> ProviderStatus:
    if number is None or number < 1:
        raise ValueError("provider number must be positive")
    cache_seconds = max(0, int(os.environ.get("PROVIDER_STATUS_CACHE_SECONDS", "0")))
    cache_key = (provider, repository, number)
    cached = _STATUS_CACHE.get(cache_key)
    if cache_seconds and cached and time.monotonic() - cached[0] < cache_seconds:
        return cached[1]
    if provider == "github":
        url = f"https://api.github.com/repos/{repository}/pulls/{number}"
        headers = {"Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}"}
    elif provider == "gitlab":
        url = f"https://gitlab.com/api/v4/projects/{quote(repository, safe='')}/merge_requests/{number}"
        headers = {"Accept": "application/json", "PRIVATE-TOKEN": token}
    else:
        raise ValueError("unsupported provider")
    breaker = breaker_for(provider)
    breaker.before_call()
    try:
        response = transport(Request(url, headers=headers), timeout=10)
        payload = json.loads(response.read().decode())
        validate_status_payload(provider, payload)
        breaker.success()
    except HTTPError as exc:
        breaker.failure()
        if exc.code == 429:
            value = exc.headers.get("Retry-After") if exc.headers else None
            raise ProviderRateLimited(int(value) if value and value.isdigit() else None, "provider rate limit exceeded") from exc
        raise RuntimeError(f"provider returned HTTP {exc.code}") from exc
    except (URLError, TimeoutError, json.JSONDecodeError) as exc:
        breaker.failure()
        raise RuntimeError("provider status request failed") from exc
    if provider == "github":
        merged = bool(payload.get("merged_at"))
        state = "merged" if merged else str(payload.get("state") or "unknown")
    else:
        state = str(payload.get("state") or "unknown")
        merged = state == "merged"
    result = ProviderStatus(state=state, merged=merged, detail={"provider": provider, "state": state, "merged": merged})
    if cache_seconds:
        _STATUS_CACHE[cache_key] = (time.monotonic(), result)
    return result
