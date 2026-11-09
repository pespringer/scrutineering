import pytest

from src.scan.evidence import build_evidence


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
