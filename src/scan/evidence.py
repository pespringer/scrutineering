"""Deterministic builders for the signed evidence contract."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any


class EvidenceVerificationError(ValueError):
    """Raised when evidence integrity or signature verification fails."""


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def build_evidence(
    *,
    artifact: bytes | dict[str, Any],
    artifact_type: str,
    format: str,
    subject_digest: str,
    tool_name: str,
    tool_version: str,
    signature_provider: str,
    signature_identity: str,
    signature_value: str,
    repository: str | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build a schema-compatible envelope; signing remains provider-owned."""
    if not subject_digest.startswith("sha256:") or len(subject_digest) != 71:
        raise ValueError("subject_digest must be a sha256 digest")
    artifact_bytes = (
        json.dumps(artifact, sort_keys=True, separators=(",", ":")).encode()
        if isinstance(artifact, dict) else artifact
    )
    timestamp = generated_at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    subject = {"digest": subject_digest}
    if repository:
        subject["repository"] = repository
    return {
        "version": "1.0.0",
        "artifactType": artifact_type,
        "format": format,
        "subject": subject,
        "artifactDigest": _sha256(artifact_bytes),
        "generatedAt": timestamp,
        "tool": {"name": tool_name, "version": tool_version},
        "signature": {
            "provider": signature_provider,
            "identity": signature_identity,
            "value": signature_value,
        },
    }


def verify_evidence(
    envelope: dict[str, Any],
    artifact: bytes | dict[str, Any],
    signature_verifier,
) -> bool:
    """Verify artifact integrity and delegate signature verification to a provider."""
    if not isinstance(envelope, dict) or envelope.get("version") != "1.0.0":
        raise EvidenceVerificationError("unsupported evidence contract")
    artifact_bytes = (
        json.dumps(artifact, sort_keys=True, separators=(",", ":")).encode()
        if isinstance(artifact, dict) else artifact
    )
    if envelope.get("artifactDigest") != _sha256(artifact_bytes):
        raise EvidenceVerificationError("artifact digest does not match evidence")
    signature = envelope.get("signature") or {}
    if not all(signature.get(key) for key in ("provider", "identity", "value")):
        raise EvidenceVerificationError("evidence signature is incomplete")
    try:
        valid = signature_verifier(envelope, artifact_bytes)
    except Exception as exc:
        raise EvidenceVerificationError(f"signature verification failed: {exc}") from exc
    if not valid:
        raise EvidenceVerificationError("signature verification failed")
    return True
