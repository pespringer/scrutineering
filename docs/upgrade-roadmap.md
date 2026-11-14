# Scrutineering Upgrade Roadmap

## Goal

Turn Scrutineering into a trustworthy security control plane: one coherent API and dashboard, evidence-backed vulnerability decisions, guarded autonomous remediation, and production-grade runtime monitoring.

The current practical completion plan is documented in
[`docs/meaningful-milestone-plan.md`](meaningful-milestone-plan.md). It
prioritizes authenticated access, real container scanning, finding lifecycle,
and one verified remediation loop before commercial expansion.

## Current Baseline

- Node.js planner logic and Python scanning/runtime services are split across separate control paths.
- `dashboard/` is the only supported frontend; the legacy `web/` tree was removed in Batch 3.
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
- **Completed:** Python database modules fail closed without `DATABASE_URL`; tests use an explicit in-memory mode, and `dashboard/` is the only supported frontend.
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
- **Completed:** provider merge callbacks without deployment evidence now queue a correlated worker-visible follow-up scan and persist a pending verification state instead of treating missing callback fields as an immediate rollback.
- **Completed:** deployment evidence can now close a pending publication from its persisted correlated scan without requiring operators to copy scan counts into a second payload.
- **Completed:** release workflows can now submit signed deployment digest evidence with replay protection; the API derives the correlated scan result and closes the pending publication fail-closed.
- **Deferred:** replace manual/GitHub-specific deployment evidence submission with provider-neutral collectors that discover artifact and deployed digests, rollout state, and evidence provenance inside Scrutineering; retain signed callbacks only as a fallback for unreachable environments.
- **Started:** provider-neutral Docker/Compose and Kubernetes collectors now validate running/ready workloads, require one immutable digest, reject unhealthy Docker containers, emit redaction-safe evidence fingerprints, can be queued by repository target, and have explicit Docker overlay/Kubernetes RBAC wiring; live rollout adapters and deployment-backed verification remain.

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

### Batch 2 — Remediation Productionization

- **Completed:** remediation lifecycle transitions emit ordered durable events
  and can recover from a persisted event stream after worker restart.
- **Completed:** exact-match parsers now cover Dockerfiles, package manifests,
  Python requirements, Go modules, and Cargo dependencies.
- **Completed:** provider-specific Node/Python validation gates generate the
  required install, test, build, SBOM, and rescan phases.
- **Completed:** GitHub App token refreshes are coalesced, publishers accept
  rotating token providers, and GitHub/GitLab branch protection can be
  verified before publication.
- **Completed:** provider publication tests cover authenticated GitHub and
  GitLab requests, idempotency, allowlists, and protected branches.

### Batch 3 — Dashboard Consolidation

- **Completed:** all supported frontend routes and documentation use
  `dashboard/` as the single Next.js application.
- **Completed:** the unreferenced legacy `web/` application and its duplicate
  dependency tree were removed after confirming no build or deployment consumer
  remained.
- **Completed:** contributor, user, setup, README, and CI-facing guidance now
  exposes one frontend install, development, and build path.
- **Completed:** CI now validates the canonical dashboard package and prevents
  the retired frontend tree from being reintroduced.

### Batch 4 — Operational Scale

- **Completed:** `ScanService` can await both local and shared Redis cache
  adapters, with bounded shared-cache entry sizes and immutable-reference keys.
- **Completed:** runtime event delivery now uses a checkpointed managed queue
  facade with retries, dead-letter accounting, and restart-safe offsets.
- **Completed:** operational Prometheus rules and a Grafana dashboard cover
  scan failure rate, scan P95 latency, and runtime dead-letter events.

### Batch 5 — Evidence and Release Controls

- **Completed:** production release evidence now applies explicit Cosign
  identity and HTTPS OIDC issuer policy before verification.
- **Completed:** tagged releases validate keyless configuration and sign planner
  and worker archives with Cosign before publishing assets.
- **Completed:** staging gates prove valid evidence passes while wrong provider,
  untrusted identity, stale evidence, and migration-chain regressions block.
- **Completed:** operator checklists and evidence documentation describe the
  release-blocking behavior and required promotion artifacts.

### Batch 6 — Production Integration and Dependency Security

- **Completed:** the dashboard dependency tree is audit-clean and its
  production build passes after lockfile-safe security updates.
- **Completed:** dashboard CI now blocks high/critical dependency advisories
  before building the production artifact.
- **Completed:** the release workflow verifies both keyless Cosign signatures
  before publishing assets, and remediation can select the same release
  evidence boundary.
- **Completed:** staging and migration-chain checks cover the deployed release
  path, with operator documentation for smoke validation and rollback.

### Batch 7 — Staging Validation and Production Readiness

- **Completed:** SQLAlchemy reserved-name and deprecated UTC timestamp warnings
  were removed without changing the public database column contract.
- **Completed:** a deterministic staging-readiness drill covers database schema
  targets, authenticated service replay protection, shared Redis cache,
  checkpointed runtime delivery, audit-head anchoring, keyless release
  evidence, and monitoring asset coverage.
- **Completed:** local CI and the GitHub CI workflow run the readiness drill
  alongside deployment, documentation, frontend, release, and test gates.
- **Documented:** operators now have a staging-readiness runbook and an
  expanded production go/no-go checklist that clearly separates local
  preflight from live staging credentials, migrations, telemetry, and rollback.

Live staging execution remains an operator gate because it requires the
deployment environment, secret store, OIDC/Cosign identity, alert receivers,
and production-like PostgreSQL/Redis services.

### Batch 8 — Dashboard Product Quality

- **Completed:** the dashboard now uses a cohesive operations-console visual
  system with persistent navigation, responsive layouts, focused typography,
  risk-aware color semantics, and reusable panels/cards.
- **Completed:** the overview is organized around active exposure, severity
  trends, risk distribution, recent scan activity, and tracked-image inventory.
- **Completed:** scan history now has status summaries, repository search,
  filter controls, readable scan metadata, and clearer success/partial/failure
  treatment.
- **Completed:** image and findings views share the same hierarchy and support
  responsive tables, severity filtering, sorting, CVE links, and fix metadata.
- **Completed:** loading skeletons, retryable errors, empty states, and
  refresh controls are explicit and tested through the production dashboard
  build and Compose healthcheck.
- **Completed:** Tailwind v4 source registration is explicit, with a bundle
  contract check preventing the dashboard from shipping without its spacing,
  typography, color, and responsive utility classes.

### Batch 9 — Live dashboard data boundary

- **Completed:** added an authenticated, read-only `/api/dashboard/*` FastAPI
  router backed by PostgreSQL models for posture, trends, scans, images, and
  findings.
- **Completed:** dashboard Next.js routes now proxy to the Python API on the
  server side, keeping API credentials out of browser JavaScript while
  retaining seed data for standalone frontend development.
- **Completed:** Compose now builds and health-checks the Python API service,
  connects the dashboard to it, and exposes port 8000 for local diagnostics.
- **Next:** add paginated server-side filtering, scan controls/status polling,
  and Kubernetes dashboard/API deployment manifests.

### Batch 10 — Operational dashboard controls

- **Completed:** dashboard APIs now return bounded page envelopes with server-
  side search and status/severity filtering for scans, images, and findings.
- **Completed:** scan submission persists a pending record, enqueues Celery,
  and exposes status polling through the dashboard proxy.
- **Completed:** Celery updates durable scan state and counters as workers move
  through running, completed, and failed states.
- **Completed:** Kubernetes API/dashboard deployments, services, probes, and
  disruption budgets are checked in with server-only API-key wiring.
- **Completed:** added a runtime dashboard smoke script that verifies the UI,
  proxy routes, and credential non-disclosure.
- **Next:** add richer findings pagination in the UI, scan cancellation, and
  authenticated user/OIDC session mapping for dashboard operators.

### Batch 11 — Operator workflow and identity context

- **Completed:** image findings now use bounded server-side pages with severity
  filtering and explicit next/previous navigation.
- **Completed:** operators can cancel pending or running scans; the API revokes
  the Celery task and preserves a durable cancelled state.
- **Completed:** dashboard proxy routes preserve verified identity headers from
  a trusted OIDC ingress, and the API exposes the mapped operator session
  without exposing proxy secrets to browser JavaScript.
- **Completed:** Compose/Kubernetes configuration documents the trusted proxy
  secret boundary and adds cancellation/session API coverage.
- **Next:** add audit-visible operator actions and role-specific dashboard
  controls for remediation workflows.

### Batch 12 — Audit-visible operator actions

- **Completed:** scan start and cancellation emit append-only `AuditLog`
  records with actor, auth method, and request context.
- **Completed:** the API exposes paginated audit records and the dashboard adds
  an Audit Trail page for operator review.
- **Completed:** migration `20261110_06_dashboard_operator_events` carries the
  cancellation event into existing PostgreSQL installations.

### Batch 13 — Role-aware dashboard controls

- **Completed:** `/api/dashboard/permissions` centralizes role-derived
  capabilities for viewing, scan management, cancellation, and remediation.
- **Completed:** scan controls are hidden from read-only users while posture,
  scans, images, and findings remain available to the `dashboard` role.
- **Completed:** local default roles and verified OIDC role claims are wired
  through Compose, Kubernetes, and the server-side dashboard proxy.
- **Next:** build remediation preview, approval, and guarded apply flows behind
  the same permission and audit boundary.

### Batch 14 — Remediation preview boundary

- **Completed:** selected open findings can produce deterministic, read-only
  remediation actions with package, CVE, severity, and fixability context.
- **Completed:** preview requests are bounded to one image and 50 findings and
  reject cross-image or unavailable-fix selections.
- **Completed:** preview responses explicitly declare that they do not mutate
  database or repository state.

### Batch 15 — Remediation approval boundary

- **Completed:** actionable previews can be persisted as `requires_review`
  remediation records with durable action rows.
- **Completed:** short-lived HMAC approval tokens are issued and verified only
  for security-operator/admin roles, with token hashes and approver provenance
  stored on the remediation.
- **Completed:** approval transitions use the existing fail-closed lifecycle
  graph and emit an audit record; repository mutation remains disabled until a
  separately deployed execution worker is available.
- **Next:** connect approved records to an isolated execution worker that
  enforces evidence, worktree, validation, PR, and rollback gates.

### Batch 16 — Isolated remediation execution boundary

- **Completed:** approved remediation records now have a dedicated Celery
  queue and execution task boundary separate from scanner work.
- **Completed:** execution requires explicit enablement and a configured
  repository root; missing adapter configuration fails closed without writes.
- **Completed:** the API can queue only approved records and emits an audit
  record for the execution request.

### Batch 17 — Remediation operations visibility

- **Completed:** the dashboard API exposes a role-protected, paginated
  remediation queue and execution status contract.
- **Completed:** the dashboard includes a Remediation Queue view linked from
  desktop and mobile navigation.
- **Completed:** the dashboard proxy preserves remediation authorization
  statuses instead of presenting role denials as backend outages.
- **Next:** implement the explicit repository execution adapter with evidence,
  worktree, validation, PR, and rollback integration before enabling writes.

### Batch 18 — Remediation execution queue

- **Completed:** approved remediation requests are isolated onto a dedicated
  Celery queue rather than sharing scanner capacity.
- **Completed:** the worker requires explicit enablement and repository-root
  configuration and never assumes that a local checkout is safe to mutate.

### Batch 19 — Fail-closed execution contract

- **Completed:** execution validates approved lifecycle state and explicit
  action file paths before any adapter can be invoked.
- **Completed:** missing adapters, missing repository roots, and incomplete
  action metadata return blocked results without repository writes.
- **Next:** wire the existing worktree/evidence/validation executor into the
  explicit adapter contract and add provider publication only after gates pass.

### Batch 20 — Durable remediation operations

- **Completed:** blocked execution attempts persist ordered remediation events
  with machine-readable reasons.
- **Completed:** the dashboard API exposes remediation events for operator
  review, while the queue UI surfaces role and execution boundaries.
- **Next:** add a full remediation detail timeline and connect successful
  validated artifacts to guarded PR publication and rollback verification.

### Batch 21 — Guarded repository execution adapter

- **Completed:** exact-match action normalization now rejects traversal,
  ambiguous, empty, and no-op edits before a worktree is created.
- **Completed:** approved work can use the existing detached-worktree executor
  with provider-derived install, test, build, SBOM, and rescan gates.
- **Completed:** release evidence is required before edits and validation run;
  missing evidence/configuration remains a durable blocked event.
- **Completed:** successful local artifacts are reported with changed files and
  commit identity; PR publication and merge remain separate guarded steps.
- **Completed:** validated remediation branches can now be handed to the
  existing allowlisted PR publishers when publication is explicitly enabled;
  PR URL, number, status, and idempotency records are persisted.
- **Next:** exercise the end-to-end flow against the configured GitHub test
  repository and verify the post-merge scan/rollback coordinator.

### Batch 22 — Publication and rollback handoff

- **Completed:** validated remediation artifacts now produce a provider-neutral
  publication plan with repository allowlisting, protected-base checks,
  evidence enforcement, idempotency, and rollback metadata.
- **Completed:** post-merge verification exposes digest, scan, and finding
  regressions as `rollback_required` with a validated revert command.
- **Completed:** dashboard proxy routes expose both handoffs without leaking
  provider credentials or bypassing the existing publisher implementations.
- **Completed:** the approved worker path now connects pushed branches to the
  provider publisher and persists PR outcomes with replay-safe keys.
- **Next:** run the live GitHub test-repository publication and callback flow.

### Batch 23 — Provider publication outcomes

- **Completed:** added an explicit, disabled-by-default GitHub/GitLab publish
  endpoint that consumes only validated publication plans.
- **Completed:** provider URL/number, request hash, status, errors, and
  idempotency keys persist in `remediation_publications` via migration
  `20261111_07`.
- **Completed:** provider tokens remain server-side and protected-branch,
  allowlist, evidence, and role gates run before network publication.
- **Next:** persist merge callbacks and feed deployed digest/finding results
  into the post-merge rollback coordinator.

### Next 10 slices — Provider-to-post-merge operations

- **Completed:** persist provider merge callbacks and publication outcomes.
- **Completed:** verify provider callback HMAC signatures and reject replayed
  event IDs.
- **Completed:** persist merge commits, observed digests, scan state, and
  finding deltas on publication records.
- **Completed:** emit durable `post_merge_verified` or `rollback_required`
  remediation events.
- **Completed:** expose publication reconciliation for pending, failed, and
  merged records.
- **Completed:** add remediation detail timeline and publication status UI.
- **Completed:** add rollback decision output with validated revert commands.
- **Completed:** keep provider credentials server-side and publication gated.
- **Completed:** add provider callback, publication, and route contract tests.
- **Next:** exercise the full provider callback and rollback path in staging
  with real webhook delivery and deployment scan evidence.

### Next 10 slices — Staging provider-to-post-merge hardening

- **Completed:** normalize GitHub and GitLab merge callbacks into one provider-neutral contract.
- **Completed:** accept native provider delivery IDs and HMAC headers while retaining the internal callback contract.
- **Completed:** persist scan status, before/after finding counts, and validated rollback commands on publications.
- **Completed:** add bounded reconciliation filtering for pending, failed, and merged publication records.
- **Completed:** add provider callback outcome metrics for rejected, duplicate, unmatched, accepted, and rollback-required events.
- **Completed:** add deterministic healthy-merge and regression rollback staging fixtures.
- **Completed:** document staging webhook setup, secret rotation, callback evidence, and rollback review.
- **Completed:** expose post-merge evidence and rollback output in remediation detail payloads.
- **Completed:** run the live staging publication against the public, protected test repository; publication record `2` created PR `1` and an idempotency retry reused it.
- **Completed:** attach signed deployment scan evidence to the merged staging publication; matching digest, completed scan, and reduced findings produced `post_merge_verified`.
- **Completed:** add callback outcome metrics, Prometheus rules, Grafana panels, and staging-readiness coverage for provider callback outcomes.
- **Completed:** verify the healthy live staging merge record and make stale publication state explicit through the reconciliation API, metric, alert, and deterministic drill.
- **Next:** verify alert delivery with a live staging receiver and attach the receiver evidence to the release record.
- **Completed:** make post-merge lifecycle events idempotent per publication so provider retries cannot duplicate verification or rollback events.
- **Next:** add scheduled stale-publication reconciliation and operator-safe recovery controls.
- **Completed:** schedule bounded stale-publication reconciliation through Celery Beat and the dedicated `remediation.normal` queue.
- **Completed:** add operator-safe stale-publication previews and idempotent, non-mutating recovery requests.
- **Completed:** attach deployment scan evidence to merged publications and re-evaluate the healthy or rollback-required decision.
- **Completed:** add dashboard recovery controls and API routes for stale publication operations.
- **Completed:** validate strict evidence fields, durable recovery states, concurrency-safe idempotency, recovery timeline details, stale queue visibility, reconciliation health, and the deterministic recovery lifecycle drill.
- **Completed:** persist idempotent release-evidence records with expected/observed digests, scan outcomes, finding deltas, and verification detail.
- **Completed:** add scheduled provider recovery polling for GitHub and GitLab with server-side credentials, bounded exponential backoff, terminal failure, and dashboard reconciliation health.
- **Completed:** add audit-visible stale-publication escalation after a configurable number of stale cycles and include the evidence table in readiness schema checks.
- **Completed:** merge the controlled staging PR through protected `main`; signed callback delivery persisted the merge commit and appended `rollback_required` because deployment digest and completed scan evidence were absent.
- **Next:** verify alert delivery with a live staging receiver and attach the receiver evidence to the release record.

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

### Slices 2–20 — Recovery evidence and operator hardening

- **Completed:** durable alert-delivery evidence, idempotent alert receipts, and publication evidence exports with canonical SHA-256 digests.
- **Completed:** audit export snapshots, bounded evidence-retention settings, and explicit opt-in purge configuration.
- **Completed:** provider rate-limit parsing, bounded retry delays, process-local circuit breaking, and recovery outcome metrics.
- **Completed:** recovery queue filters, provider-failure alerts, recovery dashboard telemetry, worker-registration regression coverage, and expanded staging-readiness checks.
- **Deferred:** live receiver delivery validation remains an operator-only slice until the receiver is available.

### Next 20 implementation-only slices

- **Completed:** add opt-in scheduled evidence retention cleanup with dry-run defaults and queue registration.
- **Completed:** add canonical evidence/audit export controls and dashboard proxy routes.
- **Completed:** add durable alert queue, deterministic deduplication keys, dead-letter state, and operator replay controls.
- **Completed:** add recovery leases, provider failure classification, circuit-breaker metrics, and operator reason codes.
- **Completed:** add recovery registration, migration, monitoring, staging-drill, and release-readiness coverage.
- **Deferred:** live receiver delivery validation remains separate and requires the external receiver setup.

### Next 20 implementation-only slices

- **Completed:** add deterministic fake-receiver execution, delivery attempts, retry/dead-letter metrics, and a dead-letter dashboard page.
- **Completed:** add bounded audit filters, signed evidence-export envelopes, provider response validation, token-rotation diagnostics, and recovery-drill fixtures.
- **Completed:** add lease-safe polling, receiver-independent release-readiness commands, dashboard proxy coverage, and dead-letter monitoring.
- **Deferred:** external alert receiver delivery remains separate and is not enabled by default.

### Next 40 implementation-only slices

- **Completed:** add versioned alert contracts, adapter protocols, payload redaction, archive manifests, and deterministic failure-plan fixtures.
- **Completed:** add queue deduplication safeguards, bulk cancel/replay foundations, queue depth telemetry, lease metrics, and operator dashboard controls.
- **Completed:** add signed evidence archive tooling, audit filtering, provider credential diagnostics, migration-chain validation, and receiver-independent chaos/recovery drills.
- **Completed:** add final recovery go-live checklist and readiness documentation without enabling external receiver delivery.
- **Deferred:** actual external receiver delivery and receiver evidence remain a separate operator gate.

### Next 40 governance and archive hardening slices

- **Completed:** add shared alert priority/schema governance, fair queue ordering, and provider-scope diagnostics without exposing credentials.
- **Completed:** add canonical JSONL audit export, gzip evidence archives, archive verification, and release-package validation.
- **Completed:** add lease heartbeat/reclaim/version guards and deterministic chaos failure plans to recovery drills.
- **Completed:** add migration-chain and go-live checklist gates to the local release workflow.
- **Deferred:** external alert receiver delivery remains disabled and must be validated separately with the operator-provided receiver.

### Next 50 receiver-independent hardening slices

- **Completed:** add retention, pagination, bounded output, changed-file, retry, provider-page, backup-manifest, and queue-starvation contracts with regression tests.
- **Completed:** enforce remediation output and changed-file limits at execution time and classify validation failures for operator review.
- **Completed:** add default-deny Kubernetes networking, restricted Pod Security Admission labels, deployment validation, and a platform-hardening release gate.
- **Completed:** document lifecycle, recovery, execution, provider, disaster-recovery, and platform controls.
- **Next:** continue wiring these contracts into database retention, dashboard bulk workflows, provider adapters, backup automation, and disaster-recovery drills.
- **Deferred:** live external alert receiver delivery and receiver evidence remain separate operator-gated slices.

### Next 50 lifecycle, operations, and resilience slices

- **Completed:** wire retention policy validation into cleanup, add deterministic backup manifests and restore preflight, and add bounded provider response/page contracts.
- **Completed:** add dashboard audit actor/event filters with paginated navigation and expose a portable backup-manifest command.
- **Completed:** preserve receiver-independent retry, execution, archive, and Kubernetes hardening gates while extending regression coverage.
- **Next:** continue wiring database backup automation, richer dashboard bulk workflows, provider adapters, and disaster-recovery evidence into production operations.
- **Deferred:** live external alert receiver delivery, receiver retries, and receiver evidence remain separate operator-gated slices.

### Next 100 live-operations follow-through slices

- **Completed:** add scan retention planning/reporting, duplicate-scan contracts, scan-health summaries, backup command scaffolding, and active inventory retention scheduling.
- **Completed:** add persisted scan health APIs, worker cache/latency metric recording, scanner lifecycle telemetry, and dashboard scan-health boundaries.
- **Completed:** add scanner failure/partial-state tracking, writable Grype database configuration, multi-scanner persistence normalization, and production smoke checks.
- **Next:** continue wiring private-registry evidence, richer dashboard bulk workflows, provider adapters, and production backup/telemetry automation.
- **Deferred:** live external alert receiver delivery, receiver retries, and receiver evidence remain separate operator-gated slices.

### Next 18 live scanning milestone slices

- **Completed:** add a dashboard-to-Celery live-scan smoke command for public images with terminal-state polling and metrics reachability checks.
- **Completed:** add bounded active-inventory scheduling through Celery Beat and cover the scheduler contract with tests.
- **Completed:** document migrations, worker health, live scan setup, public/private registry behavior, and troubleshooting.
- **Next:** execute the live smoke against the running Compose stack, then add failure, cancellation, cache, metrics, cleanup, and staging evidence assertions.
- **Deferred:** alert receiver delivery and external notification evidence remain outside this milestone.

### Next 100 operations and resilience slices

- **Completed:** add backup rotation/restore-drill contracts, export cursors, quarantine expiry, resource budgets, tenant checks, escalation policies, and SLO evaluation helpers.
- **Completed:** enforce scanner finding limits and forensic snapshot size limits, and add disaster-recovery validation to local CI.
- **Completed:** add queue starvation, backup freshness, and recovery-SLO monitoring rules plus operational configuration examples.
- **Next:** continue wiring these contracts into database automation, dashboard bulk workflows, provider adapters, and production telemetry.
- **Deferred:** live external alert receiver delivery, receiver retries, and receiver evidence remain separate operator-gated slices.

### Slices 1–30 — Database, scan reliability, and private registries

- **Completed:** add backup rotation/freshness planning and fail-closed restore preflight contracts.
- **Completed:** add scheduled scan cooldown suppression and active-scan reliability helpers.
- **Completed:** classify scanner timeout, authentication, rate-limit, missing-image, and vulnerability-database failures.
- **Completed:** add private-registry configuration diagnostics and redacted digest evidence.
- **Completed:** add dry-run rotation and registry diagnostic commands with setup/runbook coverage.
- **Next:** wire backup rotation and restore preflight into scheduled production automation after operator approval.
- **Deferred:** external alert receiver delivery and receiver evidence remain separate operator-gated slices.

### Slices 101–200 — Resilience, scale, and production promotion

- **Completed:** add remediation lease renewal, retry budgets, execution resource limits, quarantine expiry, replay guards, and tenant execution capacity controls.
- **Completed:** add deployment image/secret/security/resource checks, configuration drift detection, rollout health, and provider payload redaction/request budgets.
- **Completed:** add database archival, tenant retention, growth reports, approval-gated backup deletion, queue quotas, autoscaling recommendations, and queue recovery plans.
- **Completed:** add failover/worker-loss rehearsal contracts, scan detail UI, release promotion gate, platform maturity drill, and production gate command.
- **Completed:** add provider circuit-state diagnostics and receiver-independent production scorecard coverage.
- **Next:** add authenticated provider fixtures, deeper database restore execution, and production telemetry dashboard adoption.
- **Deferred:** external alert receiver delivery and receiver evidence remain separate operator-gated slices.

### Slices 201–300 — Live operations and production telemetry

- **Completed:** add deterministic live-scan evidence contracts covering terminal states, cancellation, cache behavior, cleanup verification, and staging evidence.
- **Completed:** add encrypted backup automation planning, freshness/retention checks, restore execution preflight, checksum and migration compatibility gates, and fail-closed confirmation requirements.
- **Completed:** add authenticated GitHub/GitLab fixture contracts, permission and branch-protection readiness checks, provider response/retry boundaries, and publication reconciliation decisions.
- **Completed:** add post-merge finding/digest reconciliation, rollback-readiness evidence, bounded bulk workflow previews, and destructive-action confirmation requirements.
- **Completed:** add a production operations dashboard with scan, queue, backup, provider, recovery, tenant, drift, worker, and release-health telemetry panels.
- **Completed:** add lifecycle archive previews, bounded batch planning, resilience scorecards, and a 100-slice receiver-independent validation manifest.
- **Completed:** expose receiver-independent production operations through `/api/dashboard/production-operations` and `/operations` without enabling external alert delivery.
- **Completed:** add `validate:production-operations` to the local release workflow and cover the contracts with regression tests.
- **Deferred:** live external alert receiver delivery, receiver retries, and receiver evidence remain separate operator-gated slices.

### Slices 301–400 — Operations execution and recovery evidence

- **Completed:** add live-scan smoke execution contracts for terminal state, metrics, cleanup, cancellation, cache, and staging evidence.
- **Completed:** add encrypted backup execution evidence, isolated restore runs, checksum/migration/timeout checks, and restore cleanup results.
- **Completed:** add authenticated provider end-to-end fixtures, deployment observation polling, finding-delta reconciliation, and rollback decisions.
- **Completed:** add bounded bulk execution summaries, telemetry history, archive execution plans, and recovery chaos scenario scoring.
- **Completed:** add production security gates for image digests, secret restrictions, drift, quotas, accessibility, and API contracts.
- **Completed:** add `drill:operations-execution` for deterministic live-scan, provider, restore, recovery, and security validation.
- **Completed:** add a 100-slice receiver-independent execution manifest covering slices 301–400.
- **Deferred:** live external alert receiver delivery, receiver retries, and receiver evidence remain separate operator-gated slices.

### Slices 401–500 — Production workflow verification

- **Completed:** add live-scan evidence bundles for public/private images, failure categories, cancellation cleanup, cache behavior, and staging runs.
- **Completed:** add approved backup scheduling, encrypted destination checks, restore record/checksum verification, and disposable-target cleanup evidence.
- **Completed:** add provider conformance reports for reads, pagination, permissions, branch protection, rate-limit recovery, and timeout recovery.
- **Completed:** add deployment polling, post-merge evidence, finding-delta decisions, rollback-required classification, and bounded dashboard workflow previews.
- **Completed:** add telemetry trend-series contracts, lifecycle execution verification, recovery-time reporting, and production security evidence.
- **Completed:** add `drill:production-workflows` for deterministic scan, backup, restore, provider, publication, recovery, and release checks.
- **Completed:** add a 100-slice receiver-independent workflow manifest covering slices 401–500.
- **Deferred:** live external alert receiver delivery, receiver retries, and receiver evidence remain separate operator-gated slices.

### Slices 501–600 — Production maturity and promotion readiness

- **Completed:** add scan orchestration reports, tenant/concurrency controls, scanner/database version evidence, reproducibility checks, and failure-rate helpers.
- **Completed:** add backup destination health, key-age checks, restore audit records, provider credential/permission/allowlist readiness, and publication replay keys.
- **Completed:** add dashboard report contracts, percentile and trend analytics, database quality metrics, scaling recommendations, and identity-security scorecards.
- **Completed:** add documentation freshness checks, API/throughput/migration/load-test promotion gates, and receiver-independent maturity evidence.
- **Completed:** add `drill:production-maturity` for scan, backup, provider, database, scaling, security, and promotion checks.
- **Completed:** add a 100-slice receiver-independent maturity manifest covering slices 501–600.
- **Deferred:** live external alert receiver delivery, receiver retries, and receiver evidence remain separate operator-gated slices.

### Slices 601–700 — v1.0 readiness and operational integration

- **Completed:** add persistent scan platform state, tenant scheduling/fairness checks, scanner/database freshness, replay keys, and scan readiness scoring.
- **Completed:** add backup failover planning, encryption-key checks, restore lifecycle progress, record verification, provider credential lifecycle, and branch-policy readiness.
- **Completed:** add saved dashboard view contracts, bounded telemetry queries, database growth forecasting, quality checks, and scaling recommendations.
- **Completed:** add identity/security gates, documentation inventory checks, benchmark inputs, migration/load-test gates, and the receiver-independent v1.0 promotion gate.
- **Completed:** add `drill:v1-readiness` for scan, backup, provider, database, scaling, security, and promotion checks.
- **Completed:** add a 100-slice receiver-independent v1.0 manifest covering slices 601–700.
- **Deferred:** live external alert receiver delivery, receiver retries, and receiver evidence remain separate operator-gated slices.

### Slices 701–900 — v1.1 hardening and promotion

- **Completed:** add scan/registry/database reliability contracts, cache/replay policies, lifecycle quality checks, backup recovery, provider lifecycle, and publication state gates.
- **Completed:** add dashboard accessibility, telemetry quality, SLO, capacity, identity/audit, security baseline, disaster-recovery, and Kubernetes readiness contracts.
- **Completed:** add compliance traceability, v1.1 promotion scoring, and a 200-slice receiver-independent manifest.
- **Completed:** add `drill:v1-1-readiness` for the v1.1 hardening and promotion checks.
- **Deferred:** live external alert receiver delivery, receiver retries, and receiver evidence remain separate operator-gated slices.

### Slices 71–100 — Provider, recovery, and observability operations

- **Completed:** add provider capability/permission diagnostics, outage classification, response outcome metrics, and safe dashboard diagnostics.
- **Completed:** add backup/restore readiness checks, deterministic provider/queue/worker/restore failure drills, and release-health evaluation.
- **Completed:** add queue, backup, provider-request, and SLO Prometheus metrics with operational alert rules.
- **Completed:** add receiver-independent release-health reporting and operator documentation.
- **Next:** add provider-specific authenticated fixtures, deeper failover simulations, and production telemetry dashboards.
- **Deferred:** external alert receiver delivery and receiver evidence remain separate operator-gated slices.

### Slices 31–70 — Dashboard bulk operations and private-registry readiness

- **Completed:** add durable scan archive state, finding acknowledgement/assignment state, and migration `20261113_16`.
- **Completed:** add bounded bulk scan cancel/retry/archive controls with audit events and isolated retry identities.
- **Completed:** add bulk image archive, finding acknowledgement, assignment, and deterministic findings export APIs.
- **Completed:** add dashboard proxy routes and scan/finding selection controls for operator workflows.
- **Completed:** add scheduled dry-run backup freshness/rotation reporting and restore-safe operational documentation.
- **Completed:** add private-registry scan diagnostics, redacted evidence payloads, and failure categories for operator review.
- **Next:** add provider-specific authenticated end-to-end fixtures and production backup execution automation after approval.
- **Deferred:** external alert receiver delivery and receiver evidence remain separate operator-gated slices.

### Practical milestone — live scan to dashboard findings

- **Completed:** wire the dashboard scan action to the real API, Celery worker,
  Trivy/Grype execution, PostgreSQL persistence, and a persisted findings API.
- **Completed:** expose fixable findings in scan detail and preserve the guarded
  remediation proposal boundary; execution remains approval-gated.
- **Completed:** Compose now mounts a disposable remediation checkout and signed
  evidence directory into the worker and includes Git, Trivy, Grype, and Cosign.
- **Verified locally:** the Compose stack queued and completed a real `alpine:3.20`
  scan with both scanners and a durable scan record.
- **Verified locally:** the supported dashboard smoke queued two repeat `alpine:3.20`
  scans, confirmed both terminal records and stable persisted findings, and
  verified the findings endpoint identity for each run.
- **Completed:** dashboard remediation proposals preserve the checkout directory
  for filesystem scan findings, allowing the approval-gated worker to apply the
  same source coordinate returned by the scanner.
- **Next:** exercise the guarded
  remediation proposal, provider PR publication, and post-merge verification with
  the configured GitHub test project.
- **Deferred:** live external alert receiver delivery remains separately gated.
