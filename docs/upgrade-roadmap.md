# Scrutineering Upgrade Roadmap

## Goal

Turn Scrutineering into a trustworthy security control plane: one coherent API and dashboard, evidence-backed vulnerability decisions, guarded autonomous remediation, and production-grade runtime monitoring.

## Current Baseline

- Node.js planner logic and Python scanning/runtime services are split across separate control paths.
- `dashboard/` is now the canonical frontend; `web/` remains a legacy tree pending removal.
- Remediation currently produces deterministic PR artifacts; it does not yet patch, validate, or merge repositories.
- The planner now has API-key authentication, request IDs, structured errors, and process-local rate limiting; OIDC/RBAC, complete schema validation, and distributed limiting remain.
- Compose keeps PostgreSQL and Redis internal by default and requires explicit credentials.
- Scanner orchestration, observability, and finding lifecycle management need hardening.

## Phase 0 — Restore Trust (now)

- Keep `npm test` green and make fixtures reflect fail-closed policy semantics.
- Make Python test dependencies reproducible from `requirements.txt`.
- Add API contract tests and a documented local CI command.
- Treat partial scans, missing evidence, and stale vulnerability databases as explicit non-passing states.

## Phase 1 — Establish a Secure Core (0–30 days)

- **Started:** planner API key enforcement and regression coverage are implemented; OIDC/RBAC remains outstanding.
- **Started:** planner routes now have credential-scoped process-local request limiting with structured `429` responses; distributed limiting remains outstanding.
- **Started:** image references now have canonical digest-aware parsing; tag-only references remain explicitly mutable until registry digest resolution is wired into the scan boundary.
- **Started:** scan models and migrations now carry scanner/database provenance maps and per-finding database-version evidence.
- **Started:** remediation status changes now pass through a fail-closed transition graph with terminal-state protection.
- **Started:** signed SBOM/provenance evidence now has a versioned schema, fixtures, and CI validation hook; generation and signature verification remain outstanding.
- **Started:** Compose now keeps PostgreSQL and Redis internal by default and requires explicit credentials; host access is opt-in through `docker-compose.host-access.yml`.
- **Started:** scanner tasks now execute configured scanners concurrently while preserving deterministic result order.
- **Started:** Python database modules now fail closed without `DATABASE_URL`; tests use an explicit in-memory mode, and `dashboard/` is canonical while `web/` is legacy.
- **Started:** `dashboard/` is canonical and `web/` is explicitly marked legacy; removal awaits downstream migration.
- **Started:** planner API v1 is documented; scan, findings, alerts, and audit endpoints still need to converge on it.
- **In progress:** request IDs, structured errors, API keys, and process-local limits exist; OIDC/RBAC, tenant boundaries, and immutable audit records remain.
- **Started:** state services are internal by default and credentials are explicit; non-root containers remain.
- **Completed:** planner and worker images now run as unprivileged users, and Grype is installed from a pinned release archive.
- **Completed:** provider-neutral principal, role, and tenant-scope authorization primitives are covered by Node tests; JWT/OIDC verification remains an integration task.
- **Completed:** planner v1 now validates required request fields consistently across plans, PRs, CI checks, and rollout evaluation.
- **Started:** digest-aware identities and provenance fields exist; local Docker registry resolution now rejects tag-only results without a digest, while universal scan population remains.

## Phase 2 — Make Remediation Real (30–60 days)

- Add isolated worktree patching with parser-aware edits.
- Run dependency installation, tests, builds, SBOM generation, and post-change rescans before opening a PR.
- Integrate GitHub/GitLab using least-privilege credentials and signed evidence artifacts.
- Model remediation as an explicit state machine with retry, approval, rollback, and post-merge verification.

## Phase 3 — Production Operations (60–90 days)

- **Started:** Trivy and Grype run concurrently with bounded retries and per-scanner circuit breakers; caching and queue priorities remain.
- Add OpenTelemetry traces and SLOs for scan latency, failures, stale data, remediation success, and rollback rate.
- Harden eBPF/runtime monitoring with capability checks, backpressure, durable event delivery, and degraded-health reporting.
- **Started:** SBOM/provenance contract validation and deterministic evidence-envelope generation exist; provider signing, migration tests, and staging rollback drills remain.

## Definition of Done

The first production release requires green Node and Python suites, authenticated control-plane endpoints, no default production credentials, digest-based evidence, one supported dashboard, a tested rollback path, and a staging run that proves a failed policy or CI check cannot auto-merge.
