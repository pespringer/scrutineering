# Release Evidence Gates

Production releases are blocked unless keyless evidence policy is configured:

- `COSIGN_CERTIFICATE_IDENTITY` identifies the trusted workflow certificate.
- `COSIGN_OIDC_ISSUER` must be HTTPS and normally points to the GitHub Actions
  OIDC issuer.
- `RELEASE_EVIDENCE_REQUIRED` must remain `true`.

Run the deterministic staging gate locally with:

```bash
npm run drill:staging-evidence
```

It accepts one valid Cosign-style provenance envelope and proves that wrong
providers, untrusted identities, and stale evidence are release-blocking. The
production release workflow validates the same configuration before building,
then signs planner and worker archives with `cosign sign-blob --yes` and uploads
the signatures and certificates with the release assets.

The database migration chain is tested to ensure audit-anchor persistence stays
available alongside release evidence controls. Apply migrations before enabling
production remediation or promotion.
