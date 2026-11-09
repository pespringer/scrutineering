# Container Sentinel — Database Schema Design

## Overview

PostgreSQL 16 is the primary data store. The schema is managed via **Alembic** migrations and backed by **SQLAlchemy 2.0** ORM models.

## Table Summary

| Table | Purpose | Key Columns |
|---|---|---|
| `images` | Tracked container images | `registry`, `repo_name`, `tag`, `active` |
| `scans` | Individual scan executions (per image) | `scan_id`, `image_id`, `status`, counters |
| `scan_findings` | Deduplicated vulnerability findings | `fingerprint`, `severity`, `remediated` |
| `raw_scan_results` | Full JSON output from scanners (audit) | `scanner_source`, `raw_output` (JSONB) |
| `severity_snapshots` | Daily severity counts for trend charts | `snapshot_date`, counts by severity |
| `security_policies` | User-defined security rules | `policy_type`, `rules` (JSONB), `action` |
| `policy_evaluations` | Log of policy match evaluations | `violated`, `action_taken` |
| `remediations` | Auto-remediation workflow state | `status`, `pr_url`, `verified` |
| `remediation_actions` | Individual actions within a remediation | `action_type`, `before/after_value` |
| `compliance_reports` | Generated compliance report metadata | `report_format`, `scope`, `summary` |
| `audit_log` | Append-only audit trail | `event_type`, `detail`, `timestamp` |
| `container_runtime` | Runtime behaviour monitoring events | `container_id`, `event_type`, `detail` |

## Relationships

```
images ──┬──< scans
         ├──< scan_findings ──< remediations ──< remediation_actions
         │                                      └── (FK back to scan_findings)
         ├──< raw_scan_results
         ├──< severity_snapshots
         └──< container_runtime

security_policies ──< policy_evaluations
```

## Design Decisions

**Deduplication** — `scan_findings` uses a deterministic `fingerprint` column (hash of CVE + package + version). The `UniqueConstraint(fingerprint, image_id)` ensures one row per unique finding per image. `first_seen`/`last_seen` track lifecycle.

**Raw output preservation** — `raw_scan_results` stores full scanner JSONB output separately from the normalised `scan_findings` table. This keeps the findings table lean for queries while preserving forensic detail for deep analysis.

**Trend charts** — `severity_snapshots` is written once per image per day after the first scan. This avoids expensive real-time aggregation for the dashboard trend charts.

**JSONB columns** — `rules` (policies), `detail` (audit/events), `labels` (images), `raw_output` (scans), and `scope` (compliance reports) all use PostgreSQL JSONB for flexible, schema-evolving data without ALTER TABLE churn.

**Cascade deletes** — Foreign keys from `scans`, `scan_findings`, `raw_scan_results`, and `severity_snapshots` to `images` use `ON DELETE CASCADE`. Policy evaluations and remediation actions cascade from their parent rows.

**Audit trail** — `audit_log` is append-only (no UPDATE, no DELETE). All rows record `timestamp`, `event_type`, `actor`, and `detail`.

## Migration Management

```bash
# Generate new migration after model changes
cd /home/claw/paperclip/scrutineering
PYTHONPATH=. alembic -c alembic.ini revision --autogenerate -m "description"

# Run migrations
PYTHONPATH=. alembic -c alembic.ini upgrade head

# Roll back one migration
PYTHONPATH=. alembic -c alembic.ini downgrade -1
```

## Connection Configuration

Environment variables:
| Variable | Purpose | Default |
|---|---|---|
| `DATABASE_URL` | Sync URL (Celery workers) | Required deployment secret; no insecure default |
| `ASYNC_DATABASE_URL` | Async URL (FastAPI) | Optional override derived from `DATABASE_URL` |

Connection pool: 20 base, 10 overflow, 1 hour recycle, pre-ping on borrow.

## Files

| Path | Purpose |
|---|---|
| `src/db/__init__.py` | Package init, public API |
| `src/db/models.py` | All SQLAlchemy ORM models |
| `src/db/connection.py` | Engine, session factories |
| `src/db/repositories.py` | Data access layer |
| `src/db/migrations/env.py` | Alembic environment |
| `src/db/migrations/versions/*.py` | Migration scripts |
| `alembic.ini` | Alembic configuration |
