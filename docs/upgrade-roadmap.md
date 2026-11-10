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
- **Completed:** OIDC discovery metadata is fetched over HTTPS with issuer validation and bounded request timeouts.
- **Completed:** JWT verification now selects a JWKS key by `kid` and caches rotating-key metadata for a bounded interval.
- **Completed:** configured OIDC verification now composes discovery, JWKS signature verification, and claim-policy enforcement.
- **Started:** planner routes now have credential-scoped limits with a Redis-compatible distributed adapter and strict Redis URL validation; client lifecycle and deployment wiring remain.
- **Completed:** planner Redis integration now has an explicit single-client start, health-check, and shutdown lifecycle boundary.
- **Completed:** the distributed limiter now composes validated Redis configuration with the atomic Redis increment adapter.
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
- **Completed:** internal service requests now have body-bound, timestamped HMAC authentication helpers with replay-skew rejection.
- **Started:** configured API keys and an OIDC claim-policy boundary now map to verified-principal-shaped roles and tenant scopes; audit records now carry a hash chain, while provider discovery/signature wiring and durable chain anchoring remain.
- **Started:** state services are internal by default and credentials are explicit; non-root containers remain.
- **Completed:** planner and worker images now run as unprivileged users, and Grype is installed from a pinned release archive.
- **Completed:** provider-neutral principal, role, and tenant-scope authorization primitives are covered by Node tests; JWT/OIDC verification remains an integration task.
- **Completed:** planner v1 now validates required request fields consistently across plans, PRs, CI checks, and rollout evaluation.
- **Started:** digest-aware identities and provenance fields now flow through `ScanService`; local Docker resolution falls back to OCI registry manifests and production defaults to fail-closed identity, while universal credential/provider wiring remains.
- **Completed:** Docker Hub, GHCR, and GitLab registry credentials now have one explicit environment-derived mapping.
- **Completed:** registry integrations now publish explicit credential-key requirements for ECR and GCR alongside existing providers.

## Phase 2 — Make Remediation Real (30–60 days)

- **Started:** remediation workers can now verify evidence, apply injected changes, and run fail-closed validation commands inside detached Git worktrees; guarded exact-match edits exist, while language-specific parsers, commits, and PR publication remain.
- **Completed:** remediation includes conservative Dockerfile and exact dependency parsers that reject ambiguous matches.
- **Started:** remediation validation now requires install, test, build, SBOM, and post-change rescan phases in order; provider-specific commands and PR publication remain.
- **Completed:** validation commands now fail closed unless their executables are explicitly allowlisted.
- **Started:** guarded GitHub and GitLab publishers require verified evidence, allowlists, and idempotency keys; GitHub App/project-token lifecycle and branch-policy enforcement remain.
- **Completed:** GitHub App installation-token acquisition is isolated behind a scoped, expiry-aware adapter.
- **Completed:** publication idempotency records can persist in a restrictive local store instead of process memory.
- **Completed:** GitLab publication now reuses the same idempotent result for retried project requests.
- **Completed:** GitLab publication now rejects non-protected target branches by default.
- **Completed:** provider tokens and publication allowlists now load through one normalized production-checked configuration boundary.
- **Completed:** FastAPI API-key comparison now uses constant-time matching and rejects empty credentials.
- **Started:** remediation execution now has an in-memory coordinator and validated rollback-plan builder for the analyzing/patching/building/verifying/PR/completed path; persistence, approval, and post-merge verification remain.
- **Completed:** isolated remediation execution can optionally produce a local commit artifact after validation, without pushing or merging.
- **Completed:** remediation approvals now use scoped, short-lived HMAC tokens that fail closed on tampering or expiry.
- **Completed:** remediation execution now enforces configured approval tokens at the write boundary.
- **Completed:** post-merge verification now compares deployed digests, scan completion, and finding deltas before declaring success.
- **Completed:** post-merge verification now has a coordinator that invokes rollback handlers on regressions.
- **Completed:** remediation approval provenance now persists approver, timestamp, and token hash fields through an Alembic migration.
- **Completed:** remediation lifecycle events now have a durable PostgreSQL table and migration chain.
- **Completed:** evidence verification can enforce an artifact-size ceiling before invoking signature providers.

## Phase 3 — Production Operations (60–90 days)

- **Started:** Trivy and Grype run concurrently with bounded retries, per-scanner circuit breakers, a local digest-keyed TTL cache, and explicit scan queue priorities; shared caching remains.
- **Completed:** the scan cache now supports explicit invalidation and expired-entry pruning for shared-worker maintenance.
- **Completed:** a Redis-backed scan cache adapter now supports shared worker results with digest-derived keys and TTLs.
- **Completed:** scan worker configuration now validates that all priority queues are present.
- **Started:** the canonical FastAPI app exposes a Prometheus-compatible metrics registry at `/metrics`, including scanner outcomes; OpenTelemetry traces and production SLO instrumentation remain.
- **Completed:** the metrics registry exposes a lock-protected structured snapshot for diagnostics without parsing Prometheus text.
- **Completed:** the metrics registry now supports P50/P95 observations for production latency SLOs.
- **Completed:** service code now has an optional OpenTelemetry span bridge that remains usable without the SDK installed.
- **Completed:** OTLP exporter configuration now validates endpoints and provides an explicit service name.
- **Completed:** CI harness failures are no longer ignored, and the Python job sets its package path explicitly.
- **Completed:** the example environment now documents complete scan queues, provider allowlists, and evidence freshness/size controls.
- **Completed:** the composed API exposes a public version endpoint for deployment and support diagnostics.
- **Completed:** dashboard API requests now abort after a bounded timeout and always clean up their timer.
- **Started:** runtime monitoring now exposes bounded-buffer health, durable JSONL event delivery, sink-failure telemetry, and explicit eBPF capability reports; managed queue delivery remains.
- **Completed:** runtime delivery now retries failed sinks and routes exhausted events to an optional dead-letter handler.
- **Completed:** durable runtime replay supports bounded, container-scoped reads.
- **Completed:** runtime replay now has a persistent offset checkpoint for restart-safe draining.
- **Started:** SBOM/provenance verification now supports digest, signature, and freshness gates; deployment keyless-policy configuration, migration tests, and staging rollback drills remain.
- **Completed:** production cosign policy now requires an explicit certificate identity and HTTPS OIDC issuer.
- **Completed:** a deterministic staging rollback drill covers healthy, digest-drift, and finding-regression outcomes.

## Definition of Done

### Batch 1 — Identity and Provider Integration

- **Completed:** planner requests can use the configured HTTPS OIDC provider
  boundary while retaining scoped API-key authentication for bootstrap and
  local operation.
- **Completed:** the Python API can require body-bound HMAC service identities
  with bounded clock skew and replay rejection.
- **Completed:** Docker Hub, GHCR, GitLab, ECR, and GCR credentials share one
  validated environment mapping; incomplete static pairs fail closed.
- **Completed:** audit-chain heads can be externally anchored and their
  receipts persisted through migration `20261109_05`.

The current hardening batch also covers unsigned-token rejection, bounded OIDC
clock skew, Redis lifecycle health, limiter-key validation, provider branch
validation, cache size/cardinality controls, runtime replay integrity, external
audit anchoring, and CI-executed rollback drills.

The latest deployment slice also configures all scan queues in Compose and
Kubernetes, adds non-root restricted security contexts to planner and worker
pods, and bounds registry pull/authentication subprocesses.
Kubernetes promotion now also includes the checked-in namespace resource quota.

The current follow-up batch adds key-rotation refresh, service replay guards,
durable publisher idempotency, remediation event sequencing, scanner latency
metrics, dashboard CI builds, Kubernetes temporary-storage limits, and stricter
image/database/evidence validation.

This batch additionally adds bounded JWKS and database-pool configuration,
durable audit exports, deployment-manifest validation, pod disruption budgets,
Compose privilege restrictions, runtime event rotation, and deployment resource
quotas.

The latest batch also adds replay-safe service identities, concurrent Redis-start
coalescing, durable provider token/idempotency handling, redacted remediation
events, scanner latency instrumentation, locked production images, and CI-local
validation of every checked-in deployment manifest.
README documentation links are now validated as part of local CI.

This follow-up batch adds secure JWKS endpoint/key-set validation, bounded
scanner output and finding counts, service-auth skew limits, audit retention
guards, immutable post-merge digest validation, and deployment propagation of
the new safety settings.

The current batch also adds worker image health checks, scanner-limit propagation
through Compose/Kubernetes, deployment quota validation, and CI enforcement of
container and documentation checks.

It also hardens JWKS metadata validation, service clock skew, audit retention,
approval identities, scanner task identifiers, and deployment health checks.

Deployment validation now asserts worker health checks, quota memory limits, and
pod-disruption availability settings before release promotion.

The first production release requires green Node and Python suites, authenticated control-plane endpoints, no default production credentials, digest-based evidence, one supported dashboard, a tested rollback path, dashboard CI builds, and a staging run that proves a failed policy or CI check cannot auto-merge.
