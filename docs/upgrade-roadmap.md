# Scrutineering Upgrade Roadmap

## Goal

Turn Scrutineering into a trustworthy security control plane: one coherent API and dashboard, evidence-backed vulnerability decisions, guarded autonomous remediation, and production-grade runtime monitoring.

## Current Baseline

- Node.js planner logic and Python scanning/runtime services are split across separate control paths.
- `dashboard/` and `web/` overlap and target different API contracts.
- Remediation currently produces deterministic PR artifacts; it does not yet patch, validate, or merge repositories.
- The planner HTTP API has no authentication, schema validation, request tracing, or rate limiting.
- Compose exposes PostgreSQL and Redis with development credentials.
- Scanner orchestration, observability, and finding lifecycle management need hardening.

## Phase 0 — Restore Trust (now)

- Keep `npm test` green and make fixtures reflect fail-closed policy semantics.
- Make Python test dependencies reproducible from `requirements.txt`.
- Add API contract tests and a documented local CI command.
- Treat partial scans, missing evidence, and stale vulnerability databases as explicit non-passing states.

## Phase 1 — Establish a Secure Core (0–30 days)

- **Started:** planner API key enforcement and regression coverage are implemented; OIDC/RBAC remains outstanding.
- **Started:** planner routes now have process-local request limiting with structured `429` responses; distributed limiting remains outstanding.
- **Started:** image references now have canonical digest-aware parsing; tag-only references remain explicitly mutable until registry digest resolution is wired into the scan boundary.
- **Started:** scan models and migrations now carry scanner/database provenance maps and per-finding database-version evidence.
- **Started:** remediation status changes now pass through a fail-closed transition graph with terminal-state protection.
- **Started:** signed SBOM/provenance evidence now has a versioned schema, fixtures, and CI validation hook; generation and signature verification remain outstanding.
- **Started:** Compose now keeps PostgreSQL and Redis internal by default and requires explicit credentials; host access is opt-in through `docker-compose.host-access.yml`.
- **Started:** scanner tasks now execute configured scanners concurrently while preserving deterministic result order.
- **Started:** Python database modules now fail closed without `DATABASE_URL`; tests use an explicit in-memory mode, and `dashboard/` is canonical while `web/` is legacy.
- Select one frontend and deprecate the other.
- Define one versioned API contract for scans, findings, remediation runs, alerts, and audit events.
- Add OIDC authentication, RBAC, tenant boundaries, request IDs, structured errors, rate limits, and immutable audit records.
- Stop publishing database/Redis ports by default; remove default secrets; run containers as non-root.
- Identify images by immutable digest and store scanner/database versions with every result.

## Phase 2 — Make Remediation Real (30–60 days)

- Add isolated worktree patching with parser-aware edits.
- Run dependency installation, tests, builds, SBOM generation, and post-change rescans before opening a PR.
- Integrate GitHub/GitLab using least-privilege credentials and signed evidence artifacts.
- Model remediation as an explicit state machine with retry, approval, rollback, and post-merge verification.

## Phase 3 — Production Operations (60–90 days)

- Run Trivy and Grype concurrently with bounded retries, caching, queue priorities, and circuit breakers.
- Add OpenTelemetry traces and SLOs for scan latency, failures, stale data, remediation success, and rollback rate.
- Harden eBPF/runtime monitoring with capability checks, backpressure, durable event delivery, and degraded-health reporting.
- Produce SBOMs, signed images, provenance attestations, migration tests, and staging rollback drills.

## Definition of Done

The first production release requires green Node and Python suites, authenticated control-plane endpoints, no default production credentials, digest-based evidence, one supported dashboard, a tested rollback path, and a staging run that proves a failed policy or CI check cannot auto-merge.
