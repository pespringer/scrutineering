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
| PostgreSQL        | 5432  | Metadata and scan results storage    |
| Redis             | 6379  | Celery message broker                |
| Celery Worker     | -     | Runs Trivy/Grype vulnerability scans |
| Celery Beat       | -     | Schedules periodic scan tasks        |

### Database Migrations

```bash
# Apply all pending migrations
docker compose exec app alembic -c alembic.ini upgrade head

# Rollback one version
docker compose exec app alembic -c alembic.ini downgrade -1

# Generate a new migration after model changes
docker compose exec app alembic -c alembic.ini revision --autogenerate -m "description"
```

### Health Checks

```bash
curl http://localhost:3000/health
docker compose ps
```

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
- `SCHEDULE_CRON_SCAN` — Cron schedule for periodic scans (default: every 6 hours)

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
