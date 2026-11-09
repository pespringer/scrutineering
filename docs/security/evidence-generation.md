# Evidence Generation

`src.scan.evidence.build_evidence` creates deterministic v1 SBOM/provenance
envelopes from artifact bytes or canonical JSON. It computes the artifact
digest and requires an immutable subject digest before producing the envelope.

The signature fields are supplied by an external signer such as cosign,
Sigstore, or KMS. This builder does not pretend to implement cryptographic
signing or verification; deployment must obtain and verify the signature using
the selected provider before accepting evidence.
