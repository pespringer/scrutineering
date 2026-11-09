import pytest

from src.scan.evidence import EvidenceVerificationError, build_evidence, verify_evidence
from datetime import datetime, timezone


def test_build_evidence_is_deterministic_for_json_artifacts():
    kwargs = dict(
        artifact={"packages": [{"name": "openssl", "version": "3.0"}]},
        artifact_type="sbom",
        format="spdx-json",
        subject_digest="sha256:" + "a" * 64,
        tool_name="syft",
        tool_version="1.18.0",
        signature_provider="cosign",
        signature_identity="pipeline@example.test",
        signature_value="signed-value-123456",
        generated_at="2026-11-08T12:00:00Z",
    )
    first = build_evidence(**kwargs)
    second = build_evidence(**kwargs)
    assert first == second
    assert first["artifactDigest"].startswith("sha256:")


def test_evidence_rejects_mutable_subjects():
    with pytest.raises(ValueError, match="sha256 digest"):
        build_evidence(
            artifact=b"{}", artifact_type="sbom", format="spdx-json",
            subject_digest="latest", tool_name="syft", tool_version="1",
            signature_provider="cosign", signature_identity="id", signature_value="x" * 16,
        )


def test_verification_checks_digest_before_provider_signature():
    envelope = build_evidence(
        artifact={"packages": []}, artifact_type="sbom", format="spdx-json",
        subject_digest="sha256:" + "a" * 64, tool_name="syft", tool_version="1",
        signature_provider="cosign", signature_identity="id", signature_value="x" * 16,
        generated_at="2026-11-08T12:00:00Z",
    )
    calls = []
    assert verify_evidence(envelope, {"packages": []}, lambda _env, _bytes: calls.append(True) or True)
    assert calls == [True]
    with pytest.raises(EvidenceVerificationError, match="digest"):
        verify_evidence(envelope, {"packages": [{"name": "tampered"}]}, lambda *_: True)


def test_verification_fails_closed_when_provider_rejects():
    envelope = build_evidence(
        artifact=b"artifact", artifact_type="provenance", format="slsa-provenance",
        subject_digest="sha256:" + "b" * 64, tool_name="builder", tool_version="1",
        signature_provider="sigstore", signature_identity="id", signature_value="x" * 16,
        generated_at="2026-11-08T12:00:00Z",
    )
    with pytest.raises(EvidenceVerificationError, match="signature"):
        verify_evidence(envelope, b"artifact", lambda *_: False)


def test_verification_rejects_stale_evidence():
    envelope = build_evidence(
        artifact=b"artifact", artifact_type="provenance", format="slsa-provenance",
        subject_digest="sha256:" + "b" * 64, tool_name="builder", tool_version="1",
        signature_provider="sigstore", signature_identity="id", signature_value="x" * 16,
        generated_at="2026-11-08T12:00:00Z",
    )
    with pytest.raises(EvidenceVerificationError, match="stale"):
        verify_evidence(envelope, b"artifact", lambda *_: True, now=datetime(2026, 11, 9, tzinfo=timezone.utc), max_age_seconds=60)
