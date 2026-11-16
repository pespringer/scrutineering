# Scrutineering — Container Sentinel

Automated container vulnerability scanning, remediation planning, and policy enforcement.

## Architecture

> **Reset in progress.** Work follows [docs/RESET-PLAN.md](docs/RESET-PLAN.md).
> Phase 1a removed the Node planner service; later phases trim the rest.

```
scrutineering/
├── src/
│   ├── api/              # Composed FastAPI application
│   ├── analytics/        # Dashboard API routes
│   ├── scan/             # Celery workers (Trivy/Grype scans)
│   ├── remediation/      # Worktrees, edits, validation, publication
│   ├── db/               # SQLAlchemy models + Alembic migrations
│   └── telemetry/        # Prometheus metrics and tracing
├── dashboard/            # Next.js dashboard
├── k8s/                  # Kubernetes manifests
├── monitoring/           # Prometheus/Grafana/Fluentbit configs
├── scripts/              # Repository checks, smoke tests, operational scripts
├── tests/                # Python test suite
├── fixtures/             # Test fixtures
├── docs/                 # Documentation
├── Dockerfile.api        # FastAPI data API image
├── Dockerfile.worker     # Celery worker image (Trivy, Grype)
├── Dockerfile.dashboard  # Next.js dashboard image
├── Makefile              # Developer entry points
└── docker-compose.yml    # Full local stack
```

`dashboard/` is the only supported Next.js application and is packaged by
`Dockerfile.dashboard`; the former `web/`
frontend was removed in Batch 3. Runtime services require an explicit
`DATABASE_URL`; tests opt into an in-memory SQLite database through
`SCRUTINEERING_TEST_MODE=1`.

Docker Compose services are the authenticated Python data API (`api`), the
Next.js dashboard, the local registry, PostgreSQL, Redis, the Celery scanner worker,
and Celery Beat. The dashboard is available at `http://localhost:3001/dashboard`;
its server-side routes read live data through `http://api:8000` and keep the API
key out of browser JavaScript. The API is also exposed at `http://localhost:8000`
for local diagnostics. PostgreSQL and Redis stay on the
internal Compose network unless `docker-compose.host-access.yml` is explicitly
selected.
The worker image and Compose service expose health checks for early failure
detection.
The Images workspace at `http://localhost:3001/images` also reads the local
registry catalog, showing repositories, tags, immutable digests, scan state,
open findings, and scan/rescan actions in one view.

The operator workflow is documented in [Product coherence guide](docs/operations/product-coherence.md).
The dashboard shows live scan phases, durable worker outcomes, severity trends,
and an operational audit timeline; it is available at `http://localhost:3001/dashboard`.

Provider publication and callbacks are gated by explicit configuration. Use
`PYTHONPATH=. python scripts/run-staging-provider-post-merge-drill.py` to exercise normalized merge callbacks,
post-merge verification, and rollback output with deterministic fixtures.
Provider merge callbacks that do not include deployment digest evidence now
queue a correlated worker rescan and remain `pending` until that evidence is
available; see [remediation execution operations](docs/operations/remediation-execution.md)
for the `REMEDIATION_SCAN_REPOSITORY_ROOT` setting used by filesystem scans.

## Quick Start

```bash
# 1. Clone and configure
git clone <repo> scrutineering && cd scrutineering
cp .env.example .env
# Set POSTGRES_PASSWORD, DATABASE_URL, PYTHON_API_KEY, service-auth settings,
# and provider allowlists in .env before starting.

# 2. Start all services
make up   # docker compose up --build -d

# Optional: expose PostgreSQL and Redis to the host for local tooling only.
# Do not use this override on shared or production hosts.
docker compose -f docker-compose.yml -f docker-compose.host-access.yml up --build -d

# 3. Run database migrations (the API image includes Alembic)
make migrate

# 4. Verify
curl http://localhost:8000/health
curl -I http://localhost:3001/dashboard
make smoke
```

The default Compose stack also starts a persistent local OCI registry at
`http://localhost:5000`. Push images from the host using `localhost:5000`,
then scan them from the application network using `registry:5000`:

```bash
docker compose ps registry
docker tag your-image:tag localhost:5000/scrutineering-test:latest
docker push localhost:5000/scrutineering-test:latest
# Use registry:5000/scrutineering-test:latest in the dashboard scan form.
curl http://localhost:5000/v2/
```

Registry data is stored in the `registrydata` Compose volume. The development
registry uses HTTP and is intentionally enabled only for local testing; use a
TLS-protected registry and set `REGISTRY_INSECURE=false` outside local
development. See [local registry operations](docs/operations/local-registry.md)
for the complete workflow.

## Development Setup

Requires Python 3.12 with [uv](https://docs.astral.sh/uv/), Node.js 20 (for the
dashboard and repository checks), and Docker.

```bash
make test         # Python tests plus repository checks
make test-python  # Python tests only
make check        # Doc links, deployment manifests, frontend layout, release config
make fmt-check    # Ruff and Prettier (advisory until Phase 3)

# Run the composed Python API
uvicorn src.api.app:app --host 127.0.0.1 --port 8000

# Build the dashboard
cd dashboard && npm ci && npm run validate:build
```

## CI/CD

- Pull requests: Python tests, repository checks (`make check`), dashboard
  build and audit, and an advisory format check.
- Merge to main: Docker image builds and a Trivy scan of the API image.
- Tag release: GitHub release with keyless-signed image archives.

See `.github/workflows/ci.yml` and `.github/workflows/release.yml`.

## Kubernetes Deployment

```bash
# Apply manifests in order
kubectl apply -f k8s/infrastructure.yaml     # ConfigMap, Secret, postgres, redis
kubectl apply -f k8s/resource-quota.yaml
kubectl apply -f k8s/pod-disruption-budgets.yaml
kubectl apply -f k8s/infrastructure.yaml     # postgres, redis, PVCs
kubectl apply -f k8s/api-deployment.yaml
kubectl apply -f k8s/dashboard-deployment.yaml
kubectl apply -f k8s/worker-deployment.yaml
kubectl apply -f k8s/celery-beat-deployment.yaml
kubectl apply -f k8s/services.yaml
```

Production promotion should also confirm the API and worker health checks
are passing before increasing scan concurrency.
The API and dashboard deployments use separate ClusterIP services; the
dashboard calls the API server-side with `PYTHON_API_KEY`, which must remain in
the Kubernetes Secret and never in a `NEXT_PUBLIC_*` variable. If an ingress
verifies OIDC, it may forward `x-authenticated-sub`, `x-authenticated-email`,
and `x-authenticated-roles` with the server-only `DASHBOARD_TRUSTED_PROXY_SECRET`.

## Monitoring

- Runtime monitoring APIs are documented in `docs/operations/` and exposed by
  the Python monitoring router. The canonical FastAPI app exposes Prometheus
  text metrics at `/metrics`.
- Grafana/Prometheus configuration lives in `monitoring/`.
- Batch 4 adds shared Redis scan-cache support, checkpointed managed runtime
  delivery, Prometheus SLO alerts, and a starter Grafana operations dashboard.

## Control-Plane APIs

- Scan data reads: `/api/v1/scans`, `/api/v1/findings`, `/api/v1/alerts`, and
  `/api/v1/audit`; see [Scan Data API v1](docs/api/scan-data-v1.md).
- Dashboard data and controls: see [Dashboard API v1](docs/api/dashboard-v1.md).
- Internal Python requests can use body-bound HMAC headers signed with
  `SERVICE_AUTH_SECRET`; set `SERVICE_AUTH_REQUIRED=true` when every protected
  API request must come from an authenticated service identity. Replays are
  rejected and `SERVICE_AUTH_MAX_SKEW_SECONDS` is bounded.
- The composed Python API is `src.api.app:app`; it mounts scan-data, runtime,
  analytics, dashboard, and forensics routers and exposes `/health`.
  `/ready` checks database connectivity for deployment probes.
  `/version` reports the configured service version and revision.

Production scan policy should set `REQUIRE_IMMUTABLE_SCAN_IDENTITY=true` so
tag-only images fail closed when a digest cannot be resolved. Evidence must be
verified before remediation. The executor runs isolated validation, and the
GitHub publisher can open allowlisted PRs only after verified evidence; neither
component merges or bypasses branch protection.
The scanner also defaults this policy on when `NODE_ENV=production`.
Scanner workers also enforce bounded output and finding counts through the
documented `SCANNER_MAX_OUTPUT_BYTES` and `SCANNER_MAX_FINDINGS` settings.
Production publication also requires `GITHUB_ALLOWED_REPOSITORIES` and
`GITLAB_ALLOWED_PROJECTS` to constrain provider writes.
Set `REQUIRE_BRANCH_PROTECTION=true` so GitHub and GitLab publishers verify
the target branch with the provider API immediately before publication.
Registry authentication uses one validated environment mapping for Docker Hub,
GHCR, GitLab, ECR, and GCR. Partial static credential pairs fail closed; see
`src/scan/registry.py` and `docs/setup-guide.md`.
Kubernetes API and worker deployments run as non-root with restricted privilege.
Set `COSIGN_CERTIFICATE_IDENTITY`, `COSIGN_OIDC_ISSUER`, and evidence limits in
production; set `OTEL_EXPORTER_OTLP_ENDPOINT` only when an exporter is ready.
Production release archives are signed with Cosign keyless signing in
`.github/workflows/release.yml`; promotion fails before image publication when
the identity or issuer policy is missing.
The workflow verifies both archive signatures before creating the GitHub
release, and remediation execution can select the same policy with
`release_evidence=True`.
The dashboard CI job also runs `npm audit --audit-level=high`; the checked-in
dashboard lockfile currently reports zero vulnerabilities.
Batch 8 also gives the dashboard a production-style operations-console UI with
risk-first posture summaries, severity trends, scan triage, responsive image
inventory, and explicit loading/error/empty states. Open it at
`http://localhost:3001/dashboard` after `docker compose up --build -d`.
The dashboard now uses the authenticated Python data API when Compose sets
`DASHBOARD_API_URL`; seed data remains available for standalone frontend work
when that variable is unset.
Scan history supports server-side search, status filters, pagination, targeted
scan submission, and polling of queued scan status. Apply database migrations
before using scan controls.
The Audit Trail is available at `/audit`; local operator access defaults to the
roles in `DASHBOARD_DEFAULT_ROLES`, while production roles come from the
verified OIDC ingress identity.
Remediation previews and approvals are API-gated and require
`REMEDIATION_APPROVAL_SECRET`; they do not mutate repositories until the
execution worker and its validation gates are explicitly enabled.
The Remediation Queue is available at `/remediations` for users with the
`remediator` or `security-operator` role; execution remains disabled by
default through `REMEDIATION_EXECUTION_ENABLED=false`.
Execution events are retained with the remediation record so blocked work is
visible and reviewable rather than silently discarded.
The guarded adapter also requires explicit evidence files and validation
provider/ecosystem settings; it creates detached-worktree artifacts and never
publishes or merges a change automatically.
Validated artifacts can produce a provider handoff plan, but publication still
requires the existing allowlisted GitHub/GitLab publisher boundary and
post-merge verification.
Live publication is disabled by default and requires explicit provider tokens,
repository allowlists, and `REMEDIATION_PUBLICATION_ENABLED=true`.
Set `REMEDIATION_PUBLICATION_STALE_SECONDS` (default `900`) to control when
pending, failed, or unverified merged publications appear in the stale
reconciliation view and trigger the stale-publication alert.
Provider callbacks require separate HMAC webhook secrets and are replay-safe;
merge verification and rollback-required outcomes are retained in the
remediation timeline.

## Documentation

- [Architecture Decision Records](docs/adr/)
- [Database Schema Design](docs/db-schema-design.md)
- [Operations Playbook](docs/operations/on-call-playbook.md)
- [GitHub and Cloudflare staging callback setup](docs/operations/github-cloudflare-staging.md)
- [GitHub Publication Boundary](docs/operations/github-publication.md)
- [GitLab Publication Boundary](docs/operations/gitlab-publication.md)
- [Remediation Execution](docs/operations/remediation-execution.md)
- [Evidence Generation and Verification](docs/security/evidence-generation.md)
- [Release Evidence Gates](docs/operations/release-evidence-gates.md)
- [Audit Integrity](docs/security/audit-integrity.md)
- [Provider Integration](docs/security/provider-integration.md)
- [Scan Queue Priorities](docs/operations/scan-queues.md)
- [Runtime Backpressure](docs/operations/runtime-backpressure.md)
- [Remediation Telemetry and SLOs](docs/operations/remediation-telemetry-slos.md)
- [Production Readiness Checklist](docs/operations/production-readiness-checklist.md)
- [Reset Plan](docs/RESET-PLAN.md) (current work; supersedes the upgrade roadmap)
- [Upgrade Roadmap](docs/upgrade-roadmap.md)
- [Dashboard Operations](docs/operations/dashboard.md)
- Deployment manifests can be checked with `make check`.
- [Staging Readiness Validation](docs/operations/staging-readiness.md)
- [Production Readiness Checklist](docs/operations/production-readiness-checklist.md)
