# Scrutineering — Container Sentinel

Automated container vulnerability scanning, remediation planning, and policy enforcement.

## Architecture

```
scrutineering/
├── src/
│   ├── planner/          # Node.js remediation planner API
│   ├── ci/               # CI provider integration (GitHub/GitLab)
│   ├── pr-generator/     # Automated PR generation for fixes
│   ├── harness/          # Remediation dry-run test harness
│   ├── verification/     # Policy verification harness
│   ├── rollout/          # Staged rollout controller
│   ├── telemetry/        # SLO/SLI and outcome reporting
│   ├── auth/              # API-key and OIDC claim policy boundaries
│   ├── api/               # Composed FastAPI application
│   ├── remediation/       # Worktrees, edits, validation, lifecycle, rollback
│   ├── scan/             # Python Celery workers (Trivy/Grype scans)
│   └── db/               # SQLAlchemy models + Alembic migrations
├── k8s/                  # Kubernetes manifests
├── monitoring/           # Prometheus/Grafana/Fluentbit configs
├── schemas/              # Policy and signed-evidence JSON schemas
├── scripts/              # CLI utility scripts
├── tests/                # Python test suite
├── fixtures/             # Test fixtures
├── docs/                 # Full documentation
│   ├── adr/              # Architecture decision records
│   ├── hiring/           # Hiring pipeline docs
│   ├── operations/       # Runbooks, SLAs, playbooks
│   └── security/         # Security validation docs
├── Dockerfile.api         # Production FastAPI data API image
├── Dockerfile.dashboard   # Production Next.js dashboard image
└── docker-compose.yml     # Full local stack, including dashboard
```

`dashboard/` is the only supported Next.js application and is packaged by
`Dockerfile.dashboard`; the former `web/`
frontend was removed in Batch 3. Runtime services require an explicit
`DATABASE_URL`; tests opt into an in-memory SQLite database through
`SCRUTINEERING_TEST_MODE=1`.

Docker Compose services are the Node planner (`app`), authenticated Python data
API (`api`), Next.js dashboard, PostgreSQL, Redis, the Celery scanner worker,
and Celery Beat. The dashboard is available at `http://localhost:3001/dashboard`;
its server-side routes read live data through `http://api:8000` and keep the API
key out of browser JavaScript. The API is also exposed at `http://localhost:8000`
for local diagnostics. PostgreSQL and Redis stay on the
internal Compose network unless `docker-compose.host-access.yml` is explicitly
selected.
The worker image and Compose service expose health checks for early failure
detection.

## Quick Start

```bash
# 1. Clone and configure
git clone <repo> scrutineering && cd scrutineering
cp .env.example .env
# Set POSTGRES_PASSWORD, DATABASE_URL, PLANNER_API_KEY, service-auth settings,
# and provider allowlists in .env before starting.

# 2. Start all services
docker compose up --build -d

# Optional: expose PostgreSQL and Redis to the host for local tooling only.
# Do not use this override on shared or production hosts.
docker compose -f docker-compose.yml -f docker-compose.host-access.yml up --build -d

# 3. Run database migrations (the API image includes Alembic)
docker compose exec api alembic -c src/db/migrations/alembic.ini upgrade head

# 4. Verify
curl http://localhost:3000/health
curl http://localhost:8000/health
curl -I http://localhost:3001/dashboard
docker compose exec app node scripts/run-remediation-dry-run-harness.mjs
docker compose exec app node scripts/run-verification-harness.mjs
```

## Development Setup

```bash
# Node.js
npm install

# Python
pip install -r requirements.txt

# Run tests
npm test          # Node.js tests
PYTHONPATH=. pytest tests/ -q  # Python tests

# Validate security contracts
npm run validate:policy-contract
npm run validate:evidence-contract
npm run verify:local  # Node, Python, and security-contract checks
npm run validate:deployment  # Checked-in Compose/Kubernetes manifest checks
npm run validate:docs        # README documentation-link checks
npm run validate:frontend    # Enforce the single supported dashboard tree
npm run smoke:dashboard      # Smoke-test a running dashboard/API proxy
npm run drill:staging-evidence # Release-blocking keyless evidence scenarios
npm run drill:staging-readiness # Deterministic staging/production boundary checks
npm run validate:release       # Release policy configuration check

# Run individual scripts
node src/planner/server.mjs
node scripts/run-remediation-dry-run-harness.mjs
node scripts/run-staging-rollback-drill.mjs

# Run the composed Python API
uvicorn src.api.app:app --host 127.0.0.1 --port 8000

# Build the supported dashboard
cd dashboard && npm ci && npm run validate:build
```

## CI/CD

- PR triggers: lint, unit tests (Node.js + Python)
- PRs also validate deployment manifests and README documentation links.
- Merge to main: Docker image builds, Trivy security scan
- Tag release: Automated GitHub release with keyless-signed image archives

See `.github/workflows/ci.yml` and `.github/workflows/release.yml`.

## Kubernetes Deployment

```bash
# Apply manifests in order
kubectl apply -f k8s/infrastructure.yaml     # ConfigMap, Secret, postgres, redis
kubectl apply -f k8s/resource-quota.yaml
kubectl apply -f k8s/pod-disruption-budgets.yaml
kubectl apply -f k8s/infrastructure.yaml     # postgres, redis, PVCs
kubectl apply -f k8s/planner-deployment.yaml
kubectl apply -f k8s/api-deployment.yaml
kubectl apply -f k8s/dashboard-deployment.yaml
kubectl apply -f k8s/worker-deployment.yaml
kubectl apply -f k8s/celery-beat-deployment.yaml
kubectl apply -f k8s/services.yaml
```

Production promotion should also confirm the planner and worker health checks
are passing before increasing scan concurrency.
The API and dashboard deployments use separate ClusterIP services; the
dashboard calls the API server-side with `PYTHON_API_KEY`, which must remain in
the Kubernetes Secret and never in a `NEXT_PUBLIC_*` variable.

## Monitoring

- Runtime monitoring APIs are documented in `docs/operations/` and exposed by
  the Python monitoring router. The canonical FastAPI app exposes Prometheus
  text metrics at `/metrics`.
- Grafana/Prometheus configuration lives in `monitoring/`.
- Batch 4 adds shared Redis scan-cache support, checkpointed managed runtime
  delivery, Prometheus SLO alerts, and a starter Grafana operations dashboard.

## Policy Contract

JSON schemas in `schemas/policy-contract/`. Validate with:
```bash
node scripts/validate-policy-contract.mjs
```

## Control-Plane APIs

- Planner actions: see [Planner API v1](docs/api/planner-v1.md).
- Scan data reads: `/api/v1/scans`, `/api/v1/findings`, `/api/v1/alerts`, and
  `/api/v1/audit`; see [Scan Data API v1](docs/api/scan-data-v1.md).
- Scoped planner API keys use `PLANNER_API_KEYS_JSON`; see
  [Authorization Foundation](docs/security/authorization.md).
- OIDC deployments must validate signatures before passing claims to the OIDC
  policy boundary. The distributed limiter can use the Redis adapter described
  in [Planner API v1](docs/api/planner-v1.md).
  Discovery metadata and rotating JWKS keys are fetched from the configured HTTPS issuer with bounded timeouts and cache lifetimes.
- `startConfiguredPlannerServer()` wires HTTPS OIDC discovery, rotating JWKS
  verification, and claim-to-principal mapping into the planner request boundary.
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
OIDC verification uses HTTPS discovery and rotating JWKS keys. Kubernetes
planner and worker deployments run as non-root with restricted privilege.
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

## Documentation

- [Architecture Decision Records](docs/adr/)
- [Database Schema Design](docs/db-schema-design.md)
- [Remediation Dry-Run Harness](docs/security/remediation-dry-run-harness.md)
- [Operations Playbook](docs/operations/on-call-playbook.md)
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
- [Upgrade Roadmap](docs/upgrade-roadmap.md)
- [Dashboard Operations](docs/operations/dashboard.md)
- Deployment manifests can be checked with `npm run validate:deployment`.
- [Staging Rollback Drill](docs/operations/staging-rollback-drill.md)
- [Staging Readiness Validation](docs/operations/staging-readiness.md)
- [Production Readiness Checklist](docs/operations/production-readiness-checklist.md)
