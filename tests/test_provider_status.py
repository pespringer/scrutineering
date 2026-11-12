import json
from urllib.error import HTTPError

import pytest

from src.remediation.provider_status import ProviderCircuitBreaker, ProviderRateLimited, fetch_provider_status
from src.remediation.recovery import retry_delay_seconds


class Response:
    def __init__(self, payload):
        self.payload = payload

    def read(self):
        return json.dumps(self.payload).encode()


def test_github_status_uses_merged_at_and_auth_header():
    seen = {}

    def transport(request, timeout):
        seen.update(url=request.full_url, authorization=request.headers["Authorization"], timeout=timeout)
        return Response({"state": "closed", "merged_at": "2026-11-11T00:00:00Z"})

    result = fetch_provider_status(provider="github", repository="org/repo", number=12, token="secret", transport=transport)
    assert result.merged is True
    assert result.state == "merged"
    assert seen["authorization"] == "Bearer secret"
    assert seen["url"].endswith("/repos/org/repo/pulls/12")


def test_gitlab_status_encodes_project_path():
    seen = {}

    def transport(request, timeout):
        seen["url"] = request.full_url
        return Response({"state": "opened"})

    result = fetch_provider_status(provider="gitlab", repository="group/subgroup/repo", number=4, token="secret", transport=transport)
    assert result.merged is False
    assert "%2F" in seen["url"]


def test_retry_backoff_is_bounded_and_rejects_zero():
    assert [retry_delay_seconds(i) for i in range(1, 5)] == [15, 30, 60, 120]
    assert retry_delay_seconds(99) == 300
    with pytest.raises(ValueError):
        retry_delay_seconds(0)


def test_provider_circuit_breaker_opens_after_repeated_failures():
    breaker = ProviderCircuitBreaker(threshold=2, cooldown_seconds=60)
    breaker.failure()
    breaker.failure()
    with pytest.raises(Exception, match="circuit"):
        breaker.before_call()


def test_provider_rate_limit_exposes_retry_after():
    def transport(request, timeout):
        raise HTTPError(request.full_url, 429, "slow down", {"Retry-After": "42"}, None)

    with pytest.raises(ProviderRateLimited) as error:
        fetch_provider_status(provider="github", repository="org/repo", number=1, token="secret", transport=transport)
    assert error.value.retry_after == 42
