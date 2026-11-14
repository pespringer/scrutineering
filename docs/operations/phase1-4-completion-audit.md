# Phase 1–4 Completion Audit

Updated: 2026-11-14

This is the authoritative in-scope audit for the current Phase 1–4 goal. The
older “Started” notes in the opening roadmap sections are historical snapshots;
the later batch entries and this audit reflect the current implementation.

## Secure core

Completed and locally verifiable: API-key and trusted-proxy/OIDC role
boundaries; body-bound HMAC service authentication with replay protection;
digest-aware image identity; registry credential diagnostics; signed evidence
and Cosign policy gates; internal PostgreSQL/Redis defaults; concurrent scanner
execution; migration and request-ID checks.

Evidence: `npm test`, `npm run validate:migrations`,
`npm run validate:release`, and the authenticated API/container test suite.

## Remediation and provider operations

Completed: finding lifecycle and governance; exact-match remediation parsers;
approval-gated isolated worktrees; ordered validation and SBOM/rescan gates;
durable lifecycle events; guarded GitHub/GitLab publication adapters;
idempotency; callback normalization and replay protection; rollback decisions;
post-change verification scans; authenticated provider conformance fixtures.

Evidence: `npm run drill:provider-conformance`, the remediation-focused
container tests, and the dashboard remediation workflow.

## Production operations

Completed: Redis-backed scan caching; priority queues; checkpointed runtime
delivery with retry/dead-letter handling; Prometheus metrics and optional
OpenTelemetry spans; live Operations telemetry summaries; scheduled scan and
backup execution; durable backup/restore evidence; Kubernetes and Compose
deployment checks; dashboard build and smoke validation.

Evidence: `npm run validate:frontend`, `npm run validate:deployment`,
`npm run validate:docs`, the Python container suite, and the staging-readiness
drills.

## Explicitly deferred gates

These are intentionally excluded from this completion claim: live GitHub
publication/merge callbacks against an external repository, live deployed
image-digest observation, and external alert receiver delivery/retry/dead-letter
validation. Their re-entry requirements remain in
`docs/operations/production-readiness-checklist.md`.
