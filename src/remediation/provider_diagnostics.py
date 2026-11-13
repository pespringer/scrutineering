"""Provider capability and permission diagnostics without credential leakage."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ProviderCapabilities:
    provider: str
    can_read: bool
    can_create: bool
    can_check_protection: bool
    can_merge: bool
    missing_permissions: tuple[str, ...] = ()


_REQUIRED = {
    "github": ("pull_requests:read", "pull_requests:write", "branches:read"),
    "gitlab": ("merge_requests:read", "merge_requests:write", "protected_branches:read"),
}


def required_permissions(provider: str) -> tuple[str, ...]:
    if provider not in _REQUIRED:
        raise ValueError("unsupported provider")
    return _REQUIRED[provider]


def diagnose_capabilities(provider: str, granted: set[str] | frozenset[str]) -> ProviderCapabilities:
    required = required_permissions(provider)
    missing = tuple(permission for permission in required if permission not in granted)
    request_scope = "pull_requests" if provider == "github" else "merge_requests"
    protection_scope = "branches" if provider == "github" else "protected_branches"
    can_read = f"{request_scope}:read" not in missing
    can_create = can_read and f"{request_scope}:write" not in missing
    can_protect = can_read and f"{protection_scope}:read" not in missing
    return ProviderCapabilities(provider, can_read, can_create, can_protect, can_create, missing)


def classify_provider_outage(error: BaseException | str) -> str:
    text = str(error).lower()
    if "timeout" in text or "timed out" in text:
        return "timeout"
    if "429" in text or "rate limit" in text or "too many requests" in text:
        return "rate_limited"
    if "401" in text or "403" in text or "unauthorized" in text or "forbidden" in text:
        return "permission_denied"
    if "404" in text or "not found" in text:
        return "resource_not_found"
    return "unavailable"


def provider_request_outcome(status: int) -> str:
    if status in {401, 403}:
        return "permission_denied"
    if status == 404:
        return "not_found"
    if status == 429:
        return "rate_limited"
    if 500 <= status <= 599:
        return "unavailable"
    if 200 <= status <= 299:
        return "success"
    return "client_error"
