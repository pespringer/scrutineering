"""Safe diagnostics for private registry configuration and pull failures."""

from __future__ import annotations

from dataclasses import dataclass

from src.scan.registry import registry_env_keys


@dataclass(frozen=True)
class RegistryDiagnostic:
    registry: str
    configured: bool
    required_keys: tuple[str, ...]
    missing_keys: tuple[str, ...]
    message: str


def diagnose_registry(registry: str, env: dict[str, str]) -> RegistryDiagnostic:
    keys = registry_env_keys(registry)
    missing = tuple(key for key in keys if not env.get(key))
    if not keys:
        return RegistryDiagnostic(registry, True, (), (), "no static credential pair required")
    if missing:
        return RegistryDiagnostic(registry, False, keys, missing, "required credential configuration is incomplete")
    return RegistryDiagnostic(registry, True, keys, (), "credential configuration is present")


def classify_registry_error(error: BaseException | str) -> str:
    text = str(error).lower()
    if "unauthorized" in text or "authentication" in text or "denied" in text:
        return "authentication_failed"
    if "too many requests" in text or "rate limit" in text:
        return "rate_limited"
    if "manifest unknown" in text or "not found" in text:
        return "image_not_found"
    if "timeout" in text or "timed out" in text:
        return "registry_timeout"
    return "registry_unavailable"


def private_registry_evidence(*, registry: str, digest: str, authenticated: bool, credential_keys: tuple[str, ...] = ()) -> dict[str, object]:
    if not digest.startswith("sha256:") or len(digest) != 71:
        raise ValueError("private registry evidence requires a sha256 digest")
    return {
        "registry": registry,
        "digest": digest,
        "authenticated": authenticated,
        "credential_keys": list(credential_keys),
        "credentials_redacted": True,
    }
