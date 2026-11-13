# Development Environment Setup Guide

## Prerequisites

- Docker 24+ and Docker Compose v2
- Node.js 20.x (for local development without containers)
- Python 3.12+ (for Celery worker development)
- PostgreSQL 16 client tools (optional, for direct DB access)

## Docker Compose (Recommended)

### First Run

```bash
cp .env.example .env
docker compose up --build -d
```

### Services

| Service           | Port  | Description                          |
|-------------------|-------|--------------------------------------|
| Planner API       | 3000  | Node.js REST API and remediation planner |
| Dashboard         | 3001  | Next.js security posture UI              |
| PostgreSQL        | 5432  | Metadata and scan results storage    |
| Redis             | 6379  | Celery message broker                |
| Celery Worker     | -     | Runs Trivy/Grype vulnerability scans |
| Celery Beat       | -     | Schedules periodic scan tasks        |

### Database Migrations

```bash
# Apply all pending migrations
docker compose exec api alembic -c src/db/migrations/alembic.ini upgrade heads

# Rollback one version
docker compose exec api alembic -c src/db/migrations/alembic.ini downgrade -1

# Generate a new migration after model changes
docker compose exec api alembic -c src/db/migrations/alembic.ini revision --autogenerate -m "description"
```

### Health Checks

```bash
curl http://localhost:3000/health
curl -I http://localhost:3001/dashboard
docker compose ps
```

### Live scan smoke test

After the containers are healthy and migrations are applied, run a real public
image scan and wait for the persisted result:

```bash
npm run smoke:live-scan
```

Validate failure and cancellation handling with:

```bash
npm run verify:live-scan-edges
```

Generate a dry-run scan retention report with `npm run scan:retention-report
-- export.json`. PostgreSQL backups are planned without mutation by default;
use `npm run backup:postgres -- backups/scrutineering.dump --execute` only from
an approved backup environment.

Set `SCAN_IMAGE` for another public image. The command submits through the
dashboard, polls the API until terminal state, and checks that the metrics
endpoint is reachable. Private registries additionally require their matching
credentials in `.env`.

`partial` is a valid terminal state: it means at least one configured scanner
completed and another failed. Review the worker logs before treating it as a
clean multi-scanner result.

## Local Development (Without Containers)

### Node.js Services

```bash
# Install dependencies
npm install

# Start planner server
node src/planner/server.mjs

# Run all tests
find src -name "*.test.mjs" -exec node --test {} \;

# Run specific test
node --test src/planner/remediation-planner.test.mjs
```

### Python Services

```bash
# Install dependencies
pip install -r requirements.txt

# Run tests
pytest tests/ -v

# Start Celery worker (requires Redis running)
celery --app=src.scan.celery_app:create_celery_app worker --loglevel=info

# Start Celery Beat (requires Redis running)
celery --app=src.scan.celery_app:create_celery_app beat --loglevel=info
```

### Run Scripts

```bash
node scripts/run-remediation-dry-run-harness.mjs
node scripts/run-verification-harness.mjs
node scripts/validate-policy-contract.mjs
node scripts/generate-security-outcome-report.mjs
node scripts/generate-debrief-compliance-report.mjs
```

## Environment Variables

See `.env.example` for all available variables.

Key variables:
- `DATABASE_URL` — PostgreSQL connection string
- `REDIS_URL` — Redis connection string
- `CELERY_BROKER_URL` — Celery message broker URL
- `TRIVY_SEVERITY` — Severity levels for Trivy (default: CRITICAL,HIGH)
- `GRYPE_SEVERITY_THRESHOLD` — Minimum severity for Grype (default: High)
- `SCANNER_TIMEOUT` — Scanner timeout in seconds (default: 1800)
- `GRYPE_DB_CACHE_DIR` — Writable Grype vulnerability database cache path
- `SCHEDULE_CRON_SCAN` — Cron schedule for periodic scans (default: every 6 hours)
- `OIDC_ISSUER` and `OIDC_AUDIENCE` — HTTPS issuer and audience for planner
  provider authentication; the configured server fetches and refreshes JWKS
  metadata before accepting bearer tokens.
- `SERVICE_AUTH_SECRET` — shared secret for body-bound internal HMAC requests;
  `SERVICE_AUTH_REQUIRED=true` makes that identity mandatory on protected API
  routes.
- `DOCKERHUB_*`, `GITHUB_TOKEN`, `GITLAB_TOKEN`, `AWS_*`, and
  `GOOGLE_APPLICATION_CREDENTIALS` — normalized registry credentials. Partial
  access-key pairs are rejected during configuration loading.

## Troubleshooting

### Planner won't start
- Check that PostgreSQL and Redis containers are healthy: `docker compose ps`
- Verify DATABASE_URL and REDIS_URL in `.env`

### Celery worker issues
- Ensure Redis is running and accessible
- Check broker connection: `redis-cli ping`
- View worker logs: `docker compose logs celery-worker`

### Database connection errors
- Verify PostgreSQL is running: `docker compose exec postgres pg_isready`
- Check database exists: `docker compose exec postgres psql -U scrutineering -l`
Compose keeps planner, worker, PostgreSQL, and Redis containers from gaining
new privileges. Kubernetes additionally runs planner and worker pods as
non-root with bounded writable `/tmp` volumes.
Apply `k8s/resource-quota.yaml` in the target namespace so scanner concurrency
cannot exhaust node capacity.
Apply `k8s/pod-disruption-budgets.yaml` as well to keep one planner and worker
available during voluntary node or deployment disruptions.
The planner image uses `npm ci --omit=dev` so production dependencies match the
lockfile exactly.
The worker image exposes a lightweight import health check and Compose uses it
to detect broken worker images early.
Set `DB_POOL_SIZE` and `DB_MAX_OVERFLOW` explicitly when tuning production
database concurrency; both values are bounded by configuration validation.
## Backup and registry operations

Backups are dry-run-first. Use `npm run backup:postgres` to preview a logical
backup, then pass `--execute` only from an approved maintenance context. Use
`npm run backup:rotation-report -- <metadata.json>` to plan rotation and check
freshness; the report never deletes artifacts. Restore preflight requires a
valid manifest, an isolated target, and explicit operator confirmation.

Private registry scans require the matching credential variables in `.env`.
`npm run registry:diagnostics -- ghcr.io` reports missing variable names only;
it never prints token values. Scan results retain registry, digest, and
authentication evidence while keeping credentials redacted.

## Resilience and promotion checks

Run `npm run drill:platform-maturity` for deterministic deployment, failover,
queue, and scaling checks. The production gate consumes a JSON object through
`npm run gate:production-promotion -- <checks.json>` and blocks unless tests,
migrations, deployment, backup freshness, recovery readiness, and
configuration checks all pass.

The worker schedules a dry-run backup freshness report when
`BACKUP_METADATA_PATH` points to a JSON metadata file. Dashboard bulk scan and
finding actions require an operator or security-operator role and are recorded
in the audit chain. Findings exports are bounded and include a deterministic
SHA-256 digest for handoff.

Provider diagnostics are available at the dashboard API's
`/api/dashboard/provider-diagnostics?provider=github` endpoint for security
operators. Set only permission names in `GITHUB_GRANTED_PERMISSIONS` or
`GITLAB_GRANTED_PERMISSIONS`; never place tokens or token values in those
variables. The receiver-independent release report is available through
`npm run report:release-health -- <checks.json>`.

## Production operations dashboard

The receiver-independent operations view is available at `/operations` when the
dashboard is running. It reports scan, queue, backup, provider, recovery,
tenant, drift, worker, and release-health panel definitions through
`/api/dashboard/production-operations`. Validate the checked-in contract with:

```bash
npm run validate:production-operations
```

Run the deterministic execution drill before promoting operational changes:

```bash
npm run drill:operations-execution
```

Run the production workflow drill as well:

```bash
npm run drill:production-workflows
```

Run the production maturity drill before a promotion review:

```bash
npm run drill:production-maturity
```

It validates receiver-independent scan orchestration, backup/provider readiness,
database quality, scaling, identity security, and promotion evidence.

This validates scan evidence, backup and restore checks, provider conformance,
post-merge decisions, recovery timing, and release security evidence using
deterministic fixtures.

The drill exercises live-scan, provider, restore, recovery, and production
security contracts without contacting an external alert receiver.

External alert delivery remains deferred and is intentionally not enabled by
this dashboard or its local validation command.
