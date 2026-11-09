# Supply-Chain Evidence Contract

The v1 evidence schema defines the minimum evidence required before a scan or
remediation can be treated as release-grade. It covers signed SBOMs and SLSA
provenance attestations.

Every artifact must identify an immutable `sha256:` subject digest, its own
artifact digest, generation timestamp, producing tool and version, and a
signature from Cosign, Sigstore, or an approved KMS.

Validate the checked-in examples with:

```bash
npm run validate:evidence-contract
```

The schema is a contract hook, not a claim that the current pipeline already
generates or verifies signatures. Generation, keyless identity policy, and
registry attachment remain follow-up implementation work.
