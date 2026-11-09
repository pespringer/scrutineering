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
│   ├── scan/             # Python Celery workers (Trivy/Grype scans)
│   └── db/               # SQLAlchemy models + Alembic migrations
├── k8s/                  # Kubernetes manifests
├── monitoring/           # Prometheus/Grafana/Fluentbit configs
├── schemas/              # Policy contract JSON schemas
├── scripts/              # CLI utility scripts
├── tests/                # Python test suite
├── fixtures/             # Test fixtures
├── docs/                 # Full documentation
│   ├── adr/              # Architecture decision records
│   ├── hiring/           # Hiring pipeline docs
│   ├── operations/       # Runbooks, SLAs, playbooks
│   └── security/         # Security validation docs
│
Docker Compose Services:
  app           → Node.js planner/REST server (port 3000)
  postgres      → PostgreSQL 16 (metadata + scan results)
  redis         → Redis 7 (Celery broker)
  celery-worker → Python Celery worker (Trivy/Grype scans)
  celery-beat   → Celery scheduler for periodic scans
```

## Quick Start

```bash
# 1. Clone and configure
git clone <repo> scrutineering && cd scrutineering
cp .env.example .env
# Set POSTGRES_PASSWORD, DATABASE_URL, and PLANNER_API_KEY in .env before starting.

# 2. Start all services
docker compose up --build -d

# Optional: expose PostgreSQL and Redis to the host for local tooling only.
# Do not use this override on shared or production hosts.
docker compose -f docker-compose.yml -f docker-compose.host-access.yml up --build -d

# 3. Run database migrations
docker compose exec app alembic -c alembic.ini upgrade head

# 4. Verify
curl http://localhost:3000/health
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
pytest tests/     # Python tests

# Run individual scripts
node src/planner/server.mjs
node scripts/run-remediation-dry-run-harness.mjs
```

## CI/CD

- PR triggers: lint, unit tests (Node.js + Python)
- Merge to main: Docker image builds, Trivy security scan
- Tag release: Automated GitHub release with image artifacts

See `.github/workflows/ci.yml` and `.github/workflows/release.yml`.

## Kubernetes Deployment

```bash
# Apply manifests in order
kubectl apply -f k8s/configmap-and-secrets.yaml
kubectl apply -f k8s/infrastructure.yaml     # postgres, redis, PVCs
kubectl apply -f k8s/planner-deployment.yaml
kubectl apply -f k8s/worker-deployment.yaml
kubectl apply -f k8s/celery-beat-deployment.yaml
kubectl apply -f k8s/services.yaml
```

## Monitoring

- Prometheus scraped at `http://planner:3000/metrics`
- Grafana datasource provisioning in `monitoring/prometheus-config.yaml`
- Fluentbit log collection in `monitoring/logging.yaml`

## Policy Contract

JSON schemas in `schemas/policy-contract/`. Validate with:
```bash
node scripts/validate-policy-contract.mjs
```

## Documentation

- [Architecture Decision Records](docs/adr/)
- [Database Schema Design](docs/db-schema-design.md)
- [Remediation Dry-Run Harness](docs/security/remediation-dry-run-harness.md)
- [Operations Playbook](docs/operations/on-call-playbook.md)
- [Production Readiness Checklist](docs/operations/production-readiness-checklist.md)
