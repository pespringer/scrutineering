"""Deterministic authenticated provider fixtures for conformance drills."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from urllib.parse import urlparse

from src.remediation.provider_publishers import publish_validated_plan
from src.remediation.provider_status import fetch_provider_status


@dataclass
class FixtureResponse:
    payload: dict

    def read(self) -> bytes:
        return json.dumps(self.payload).encode()


@dataclass
class AuthenticatedProviderFixture:
    """Provider API double that enforces authentication on every call."""

    provider: str
    token: str = "fixture-token"
    repository: str = "scrutineering/fixture-app"
    requests: list[dict] = field(default_factory=list)

    def __call__(self, request, timeout: int = 20) -> FixtureResponse:
        headers = {key.lower(): value for key, value in request.header_items()}
        expected_header = "authorization" if self.provider == "github" else "private-token"
        expected_value = f"Bearer {self.token}" if self.provider == "github" else self.token
        if headers.get(expected_header) != expected_value:
            raise AssertionError(f"{self.provider} fixture received an unauthenticated request")
        self.requests.append({"url": request.full_url, "method": request.get_method(), "timeout": timeout})

        path = urlparse(request.full_url).path
        if self.provider == "github":
            if path.endswith("/protection"):
                return FixtureResponse({"required_status_checks": {"contexts": []}})
            if "/pulls/" in path:
                return FixtureResponse({"state": "closed", "merged_at": "2026-11-14T12:00:00Z"})
            return FixtureResponse({"number": 101, "html_url": "https://github.com/scrutineering/fixture-app/pull/101"})

        if path.endswith("/protected_branches/main"):
            return FixtureResponse({"name": "main", "push_access_levels": []})
        if "/merge_requests/" in path:
            return FixtureResponse({"state": "merged", "merged_at": "2026-11-14T12:00:00Z"})
        return FixtureResponse({"iid": 101, "web_url": "https://gitlab.com/scrutineering/fixture-app/-/merge_requests/101"})

    def assert_safe(self) -> None:
        if not self.requests:
            raise AssertionError("provider fixture did not receive any requests")
        if any(self.token in json.dumps(request) for request in self.requests):
            raise AssertionError("provider fixture request evidence contains the token")


def run_authenticated_provider_fixture(provider: str) -> dict:
    """Run publication and merged-status checks for one supported provider."""
    provider = provider.strip().lower()
    if provider not in {"github", "gitlab"}:
        raise ValueError("unsupported provider fixture")
    fixture = AuthenticatedProviderFixture(provider)
    publication = publish_validated_plan(
        provider=provider,
        repository=fixture.repository,
        title="Fixture remediation",
        body="Deterministic authenticated provider conformance run",
        head="auto/fixture-remediation",
        base="main",
        token=fixture.token,
        idempotency_key=f"fixture-{provider}-101",
        transport=fixture,
    )
    status = fetch_provider_status(
        provider=provider,
        repository=fixture.repository,
        number=publication.number,
        token=fixture.token,
        transport=fixture,
    )
    fixture.assert_safe()
    return {"provider": provider, "publication_number": publication.number, "status": status.state, "merged": status.merged, "request_count": len(fixture.requests)}
