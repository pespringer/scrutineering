# Scrutineering — Container Sentinel

Automated container vulnerability scanning, remediation planning, and policy enforcement.

## Architecture

> **Reset in progress.** Work follows [docs/RESET-PLAN.md](docs/RESET-PLAN.md).
> Phases 1a–1d removed the Node planner, the Python subsystems the dashboard
> never called, and the remediation side systems, and squashed the database
> migrations into one baseline. Phase 1e trimmed scripts and docs; Phase 2 fixes
> the scan and finding data model.

```
scrutineering/
├── src/
│   ├── api/              # FastAPI app; routes/, schemas.py, serializers.py
│   ├── scan/             # Celery workers (Trivy/Grype scans)
│   ├── remediation/      # Fix planning, patching, BuildKit builds, publication
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
`Dockerfile.dashboard`. Runtime services require an explicit
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

Provider merge callbacks queue a correlated worker rescan and remain `pending`
until it completes; see [remediation execution](docs/operations/remediation-execution.md).

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
# Databases created before reset Phase 1d must be recreated first; see
# "Upgrading an existing installation" in docs/RESET-PLAN.md.

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
make check        # Doc links, deployment manifests, frontend layout
make e2e          # Golden path against the running stack with real scanners
make fmt          # Apply Ruff and Prettier
make fmt-check    # Formatting, lint, and the 120-character line limit (CI)

# Run the composed Python API
uvicorn src.api.app:app --host 127.0.0.1 --port 8000

# Build the dashboard
cd dashboard && npm ci && npm run validate:build
```

## CI/CD

- Pull requests: Python tests, repository checks (`make check`), dashboard
  build and audit, and an advisory format check.
- Merge to main: Docker image builds and a Trivy scan of the API image.

See `.github/workflows/ci.yml`.

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

- The FastAPI app exposes Prometheus text metrics at `/metrics`.
- Grafana/Prometheus configuration lives in `monitoring/`.

## Control-Plane APIs

- Dashboard data and controls: see [Dashboard API v1](docs/api/dashboard-v1.md).
- Internal Python requests can use body-bound HMAC headers signed with
  `SERVICE_AUTH_SECRET`; set `SERVICE_AUTH_REQUIRED=true` when every protected
  API request must come from an authenticated service identity. Replays are
  rejected and `SERVICE_AUTH_MAX_SKEW_SECONDS` is bounded.
- The composed Python API is `src.api.app:app`; it mounts the dashboard router
  (`/api/dashboard/*`) and exposes `/health`.
  `/ready` checks database connectivity for deployment probes.
  `/version` reports the configured service version and revision.

### Current behavior and limits

- **Scans** resolve each tag to its digest and scan the pinned digest, recording
  it on the scan and image. Set `REQUIRE_IMMUTABLE_SCAN_IDENTITY=true` to fail a
  scan whose tag cannot be resolved instead of scanning by tag. Scanners collect
  every severity; transient failures are retried (`SCANNER_RETRY_ATTEMPTS`), and
  `SCANNER_TIMEOUT`, `SCANNER_MAX_OUTPUT_BYTES` and `SCANNER_MAX_FINDINGS` apply
  to both scanners. `SCHEDULE_CRON_SCAN` sets the inventory rescan schedule.
- **Private registries**: `DOCKERHUB_USERNAME`/`DOCKERHUB_PASSWORD`,
  `GITHUB_TOKEN` (ghcr.io), `GITLAB_TOKEN` (registry.gitlab.com), or
  `REGISTRY_CREDENTIALS_JSON` for any other host. A partial pair fails the scan
  with a clear reason. ECR and GCR use the standard AWS and Google credentials.
- **Dashboard access** uses the roles in `DASHBOARD_DEFAULT_ROLES` for local
  API-key sessions, or the roles forwarded by a verified OIDC ingress. The
  dashboard always reads live data from the API; there is no demo mode.
- **Remediation** is shown at `/remediations` to the `remediator` and
  `security-operator` roles. Connect an image to its source repository, propose
  fixes for selected findings, and have a security operator approve. With
  `REMEDIATION_EXECUTION_ENABLED=true` the worker patches the source, builds a
  candidate image on the rootless `buildkitd` service, and scans it; the
  remediation completes when a rescan of the image no longer shows the targeted
  findings. See [remediation execution](docs/operations/remediation-execution.md).
- **Publication**: a security operator can open a GitHub pull request with a
  verified patch (`GITHUB_TOKEN`; GitHub is the only provider). The signed
  webhook (`/api/dashboard/webhooks/github`, `GITHUB_WEBHOOK_SECRET`) reports the
  merge, and the server's own rescan of the rebuilt image completes or fails the
  remediation. See [GitHub publication](docs/operations/github-publication.md).

## Documentation

- [Reset Plan](docs/RESET-PLAN.md): current work
- [Documentation index](docs/README.md)
- [Dashboard API v1](docs/api/dashboard-v1.md)
- [Product coherence guide](docs/operations/product-coherence.md)
- [Local registry](docs/operations/local-registry.md)
- [Remediation execution](docs/operations/remediation-execution.md)
- [Product requirements](docs/PRD.md)
