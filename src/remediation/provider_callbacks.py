"""Provider-neutral merge callback normalization and signature checks."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import re


@dataclass(frozen=True)
class ProviderCallback:
    event_id: str
    event_type: str
    repository: str
    number: int
    merged: bool
    state: str
    merge_commit: str | None
    expected_digest: str
    observed_digest: str | None
    scan_status: str
    findings_before: int
    findings_after: int


def verify_signature(*, provider: str, body: bytes, signature: str, secret: str) -> bool:
    if not secret or not signature:
        return False
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    candidate = signature.removeprefix("sha256=") if provider == "github" else signature
    return bool(re.fullmatch(r"[a-f0-9]{64}", candidate)) and hmac.compare_digest(candidate, digest)


def normalize_callback(*, provider: str, payload: dict, event_id: str, event_type: str | None = None) -> ProviderCallback:
    provider = provider.lower()
    if provider == "github":
        repository_data = payload.get("repository") or {}
        repository = str(repository_data.get("full_name") if isinstance(repository_data, dict) else repository_data or "")
        number = int(payload.get("number") or payload.get("pull_request", {}).get("number") or 0)
        request = payload.get("pull_request", payload)
        merged = bool(request.get("merged") or request.get("merged_at"))
        state = str(request.get("state") or payload.get("action") or "updated")
        merge_commit = request.get("merge_commit_sha") or payload.get("merge_commit")
        event_type = event_type or str(payload.get("action") or "pull_request")
    elif provider == "gitlab":
        attributes = payload.get("object_attributes", {})
        project = payload.get("project", {})
        repository = str(project.get("path_with_namespace") or payload.get("repository") or "")
        number = int(attributes.get("iid") or payload.get("number") or 0)
        merged = bool(attributes.get("state") == "merged" or attributes.get("merged_at"))
        state = str(attributes.get("state") or payload.get("state") or "updated")
        merge_commit = attributes.get("merge_commit_sha") or payload.get("merge_commit")
        event_type = event_type or str(payload.get("event_name") or "merge_request")
    else:
        raise ValueError("provider not supported")
    return ProviderCallback(
        event_id=event_id,
        event_type=event_type,
        repository=repository,
        number=number,
        merged=merged,
        state=state,
        merge_commit=merge_commit,
        expected_digest=str(payload.get("expected_digest") or ""),
        observed_digest=payload.get("observed_digest"),
        scan_status=str(payload.get("scan_status") or "pending"),
        findings_before=int(payload.get("findings_before") or 0),
        findings_after=int(payload.get("findings_after") or 0),
    )
