# Scrutineering Upgrade Roadmap

## Goal

Turn Scrutineering into a trustworthy security control plane: one coherent API and dashboard, evidence-backed vulnerability decisions, guarded autonomous remediation, and production-grade runtime monitoring.

## Current Baseline

- Node.js planner logic and Python scanning/runtime services are split across separate control paths.
- `dashboard/` is now the canonical frontend; `web/` remains a legacy tree pending removal.
- Remediation now supports isolated validation and guarded GitHub PR publication; it does not merge repositories or bypass branch protection.
- The planner now has API-key/OIDC policy boundaries, request IDs, structured errors, route validation, and local/distributed limiter adapters; provider wiring remains.
- Compose keeps PostgreSQL and Redis internal by default and requires explicit credentials.
- Scanner orchestration, observability, and finding lifecycle management need hardening.

## Phase 0 — Restore Trust (now)

- Keep `npm test` green and make fixtures reflect fail-closed policy semantics.
- Make Python test dependencies reproducible from `requirements.txt`.
- Add API contract tests and a documented local CI command.
- **Completed:** `npm run verify:local` now mirrors the repository's Node, Python, and security-contract verification sequence.
- Treat partial scans, missing evidence, and stale vulnerability databases as explicit non-passing states; provenance freshness validation is now available.

## Phase 1 — Establish a Secure Core (0–30 days)

- **Started:** planner API key enforcement, strict OIDC configuration, and claim-policy coverage are implemented; provider discovery/signature wiring remains.
- **Started:** planner routes now have credential-scoped limits with a Redis-compatible distributed adapter and strict Redis URL validation; client lifecycle and deployment wiring remain.
- **Started:** image references now have canonical digest-aware parsing and local/OCI registry resolution; universal credential/provider wiring remains.
- **Started:** scan models and migrations now carry scanner/database provenance maps and per-finding database-version evidence.
- **Started:** remediation status changes now pass through a fail-closed transition graph with terminal-state protection.
- **Started:** signed SBOM/provenance evidence has a versioned schema, deterministic generation, fixtures, CI validation, and a cosign adapter; deployment keyless-policy wiring remains.
- **Completed:** cosign verification now has a bounded timeout and fails closed on unavailable or hung binaries.
- **Started:** Compose now keeps PostgreSQL and Redis internal by default and requires explicit credentials; host access is opt-in through `docker-compose.host-access.yml`.
- **Started:** scanner tasks now execute configured scanners concurrently while preserving deterministic result order.
- **Started:** Python database modules now fail closed without `DATABASE_URL`; tests use an explicit in-memory mode, and `dashboard/` is canonical while `web/` is legacy.
- **Started:** `dashboard/` is canonical and `web/` is explicitly marked legacy; removal awaits downstream migration.
- **Started:** the canonical FastAPI app now mounts scan-data, runtime, analytics, and forensics routers, wires scan reads to SQLAlchemy, exposes readiness, and propagates request IDs; cross-service authentication remains.
- **Started:** configured API keys and an OIDC claim-policy boundary now map to verified-principal-shaped roles and tenant scopes; audit records now carry a hash chain, while provider discovery/signature wiring and durable chain anchoring remain.
- **Started:** state services are internal by default and credentials are explicit; non-root containers remain.
- **Completed:** planner and worker images now run as unprivileged users, and Grype is installed from a pinned release archive.
- **Completed:** provider-neutral principal, role, and tenant-scope authorization primitives are covered by Node tests; JWT/OIDC verification remains an integration task.
- **Completed:** planner v1 now validates required request fields consistently across plans, PRs, CI checks, and rollout evaluation.
- **Started:** digest-aware identities and provenance fields now flow through `ScanService`; local Docker resolution falls back to OCI registry manifests and production defaults to fail-closed identity, while universal credential/provider wiring remains.

## Phase 2 — Make Remediation Real (30–60 days)

- **Started:** remediation workers can now verify evidence, apply injected changes, and run fail-closed validation commands inside detached Git worktrees; guarded exact-match edits exist, while language-specific parsers, commits, and PR publication remain.
- **Started:** remediation validation now requires install, test, build, SBOM, and post-change rescan phases in order; provider-specific commands and PR publication remain.
- **Started:** guarded GitHub and GitLab publishers require verified evidence, allowlists, and idempotency keys; GitHub App/project-token lifecycle and branch-policy enforcement remain.
- **Completed:** GitLab publication now reuses the same idempotent result for retried project requests.
- **Completed:** GitLab publication now rejects non-protected target branches by default.
- **Completed:** provider tokens and publication allowlists now load through one normalized production-checked configuration boundary.
- **Started:** remediation execution now has an in-memory coordinator and validated rollback-plan builder for the analyzing/patching/building/verifying/PR/completed path; persistence, approval, and post-merge verification remain.

## Phase 3 — Production Operations (60–90 days)

- **Started:** Trivy and Grype run concurrently with bounded retries, per-scanner circuit breakers, a local digest-keyed TTL cache, and explicit scan queue priorities; shared caching remains.
- **Started:** the canonical FastAPI app exposes a Prometheus-compatible metrics registry at `/metrics`, including scanner outcomes; OpenTelemetry traces and production SLO instrumentation remain.
- **Started:** runtime monitoring now exposes bounded-buffer health, durable JSONL event delivery, sink-failure telemetry, and explicit eBPF capability reports; managed queue delivery remains.
- **Started:** SBOM/provenance verification now supports digest, signature, and freshness gates; deployment keyless-policy configuration, migration tests, and staging rollback drills remain.

## Definition of Done

The first production release requires green Node and Python suites, authenticated control-plane endpoints, no default production credentials, digest-based evidence, one supported dashboard, a tested rollback path, and a staging run that proves a failed policy or CI check cannot auto-merge.
