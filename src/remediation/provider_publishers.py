"""Small, injectable provider clients used after all local remediation gates pass."""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class PublicationResult:
    provider: str
    repository: str
    number: int
    url: str


def _request(url: str, *, token: str, headers: dict[str, str], payload: dict | None = None, transport=urlopen):
    body = json.dumps(payload).encode() if payload is not None else None
    request = Request(url, data=body, headers={**headers, "content-type": "application/json"}, method="POST" if body else "GET")
    response = transport(request, timeout=20)
    return json.loads(response.read().decode())


def publish_validated_plan(*, provider: str, repository: str, title: str, body: str, head: str, base: str, token: str, idempotency_key: str, require_branch_protection: bool = True, transport=urlopen) -> PublicationResult:
    if not token:
        raise ValueError("provider token is required")
    if provider == "github":
        owner, repo = repository.split("/", 1)
        headers = {"accept": "application/vnd.github+json", "authorization": f"Bearer {token}", "x-github-api-version": "2022-11-28"}
        if require_branch_protection:
            _request(f"https://api.github.com/repos/{owner}/{repo}/branches/{base}/protection", token=token, headers=headers, transport=transport)
        result = _request(f"https://api.github.com/repos/{owner}/{repo}/pulls", token=token, headers=headers, payload={"title": title, "body": body, "head": head, "base": base}, transport=transport)
        return PublicationResult(provider, repository, int(result["number"]), str(result["html_url"]))
    if provider == "gitlab":
        headers = {"PRIVATE-TOKEN": token}
        if require_branch_protection:
            _request(f"https://gitlab.com/api/v4/projects/{repository}/protected_branches/{base}", token=token, headers=headers, transport=transport)
        result = _request(f"https://gitlab.com/api/v4/projects/{repository}/merge_requests", token=token, headers=headers, payload={"title": title, "description": body, "source_branch": head, "target_branch": base, "labels": "security,auto-remediation"}, transport=transport)
        return PublicationResult(provider, repository, int(result["iid"]), str(result["web_url"]))
    raise ValueError("publication provider is not supported")
