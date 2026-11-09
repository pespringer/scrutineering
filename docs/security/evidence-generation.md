# Evidence Generation

`src.scan.evidence.build_evidence` creates deterministic v1 SBOM/provenance
envelopes from artifact bytes or canonical JSON. It computes the artifact
digest and requires an immutable subject digest before producing the envelope.

The signature fields are supplied by an external signer such as cosign,
Sigstore, or KMS. This builder does not pretend to implement cryptographic
signing or verification; deployment must obtain and verify the signature using
the selected provider before accepting evidence.

`verify_evidence` verifies the canonical artifact digest first, then delegates
signature verification to the configured provider adapter. A missing or
rejected signature raises `EvidenceVerificationError`; callers should block
the scan or remediation gate rather than continue with degraded evidence.
Callers can also supply `max_age_seconds` to reject stale evidence.

`CosignVerifier` is the concrete provider adapter. It invokes
`cosign verify-blob` without a shell, passes the certificate identity and
optional OIDC issuer, and returns false on any non-zero verification result.
