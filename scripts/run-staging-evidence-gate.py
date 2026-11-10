"""Deterministic staging release gate for keyless evidence policy."""

from datetime import datetime, timezone

from src.scan.evidence import EvidenceVerificationError, build_evidence, verify_release_evidence


class StagingVerifier:
    def __init__(self, **kwargs):
        self.policy = kwargs["policy"]

    def __call__(self, envelope, _artifact):
        return (
            self.policy["identity"] == "release-workflow@example.test"
            and envelope.get("signature", {}).get("identity") == self.policy["identity"]
        )


ENV = {
    "NODE_ENV": "production",
    "COSIGN_CERTIFICATE_IDENTITY": "release-workflow@example.test",
    "COSIGN_OIDC_ISSUER": "https://token.actions.githubusercontent.com",
}
ARTIFACT = {"image": "scrutineering-planner", "digest": "sha256:" + "a" * 64}


def envelope(provider="cosign", identity="release-workflow@example.test", generated_at="2026-11-09T12:00:00Z"):
    return build_evidence(
        artifact=ARTIFACT, artifact_type="provenance", format="slsa-provenance",
        subject_digest="sha256:" + "a" * 64, tool_name="staging-builder", tool_version="1",
        signature_provider=provider, signature_identity=identity, signature_value="staging-signature",
        generated_at=generated_at,
    )


def verify(candidate):
    return verify_release_evidence(
        candidate, ARTIFACT, env=ENV,
        now=datetime(2026, 11, 9, 12, 1, tzinfo=timezone.utc), max_age_seconds=300,
        verifier_factory=StagingVerifier,
    )


assert verify(envelope()) is True
print("PASS valid keyless evidence")

for name, candidate in [
    ("wrong provider", envelope(provider="sigstore")),
    ("wrong identity", envelope(identity="untrusted@example.test")),
    ("stale evidence", envelope(generated_at="2026-11-08T12:00:00Z")),
]:
    try:
        verify(candidate)
    except EvidenceVerificationError:
        print(f"PASS {name} is release-blocking")
    else:
        raise SystemExit(f"FAIL {name} was accepted")
