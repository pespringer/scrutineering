# Container Sentinel — Database Schema Design

> PostgreSQL 16 | SQLAlchemy 2.0 | Alembic  

---

## 1. Architecture Overview

| Aspect | Choice | Rationale |
|---|---|---|
| Database | PostgreSQL 16 | JSONB for raw scanner output, robust indexing, proven at scale |
| ORM | SQLAlchemy 2.0 | Mature, well-documented, async support, Alembic for migrations |
| Migrations | Alembic | Autogenerate support, versioned schema history |
| Session | scoped + contextmanager | Thread-safe for Celery workers, async sessions for FastAPI |
| Pool | SQLAlchemy pool (20 + 10 overflow) | Sized for concurrent Celery workers |

---

## 2. Table Summary (12 tables)

| Table | Purpose | Key columns |
|---|---|---|
| `images` | Tracked container images | registry, repo_name, tag, digest |
| `scans` | Individual scan executions | scan_id (unique), image_id, digest, scanner/database versions, status, counts |
| `scan_findings` | Deduplicated vulnerabilities | fingerprint (unique per image), cve_id, severity, remediated |
| `raw_scan_results` | Raw scanner JSON for audit | image_id, scanner source/version, database version, raw_output (JSONB) |
| `severity_snapshots` | Daily severity counts for trends | image_id, snapshot_date, counts by severity |
| `security_policies` | User-defined policies | policy_type, rules (JSONB), action, image_filters |
| `policy_evaluations` | Policy evaluation audit log | policy_id, scan_id, violated, action_taken |
| `remediations` | Remediation effort lifecycle | image_id, status, pr_url, verified |
| `remediation_actions` | Individual remediation actions | remediation_id, action_type, before/after values |
| `compliance_reports` | Generated compliance report metadata | title, format, scope (JSONB), file_path |
| `audit_log` | Append-only security event log | event_type, entity, detail (JSONB), actor |
| `container_runtime` | Runtime behaviour monitoring | container_id, event_type, severity, detail (JSONB) |

---

## 3. Entity Relationships

```
images (1) ──< scans (many)
images (1) ──< scan_findings (many)
images (1) ──< raw_scan_results (many)
images (1) ──< severity_snapshots (many)
images (1) ──< remediations (many)
images (1) ──< container_runtime (many)
audit_log    >── images (optional FK, SET NULL)

scans (no child tables — scan_id used as loose FK elsewhere)

scan_findings (many) >── remediations (1)   [SET NULL on delete]

security_policies (1) ──< policy_evaluations (many)

remediations (1) ──< remediation_actions (many)   [CASCADE delete]
```

---

## 4. Key Design Decisions

### 4.1 Deduplication by Fingerprint
- `fingerprint` = deterministic hash of (CVE + package_name + package_version)
- Unique constraint: `(fingerprint, image_id)` on `scan_findings`
- Upsert logic: if fingerprint+image exists, update `last_seen`; else insert with `first_seen = now`

### 4.2 JSONB for Flexible Data
- `raw_scan_results.raw_output` — full scanner JSON, queryable via `->>` and `@>` operators
- `security_policies.rules` — policy rule definitions vary by type
- `audit_log.detail` — arbitrary event metadata
- `container_runtime.detail` — highly variable per event type

### 4.3 High-Volume Data Ingest Optimization
- All tables use `BigInteger` PKs to support > 2B rows
- Composite indexes on high-cardinality query pairs:
  - `idx_findings_cve_image` on (cve_id, image_id)
  - `idx_scans_image_status` on (image_id, status)
- `pool_pre_ping=True` prevents stale connection errors
- `statement_timeout = 300000` (5 min) safety net

### 4.4 Data Retention Policies
- `SeveritySnapshot`: one row per image per day. Old data can be archived or aggregated.
- `RawScanResults`: full JSON retained indefinitely for audit. Implement periodic cleanup via cron (TODO: future issue).
- `AuditLog`: append-only but can be archived to cold storage for compliance.
- `ContainerRuntime`: high-volume — implement TTL-based cleanup (e.g., 90 days).

### 4.5 Encrypted Storage
- Sensitive data (tokens, credentials) should **never** be stored in this schema.
- Use environment variables or a secrets manager (Hashicorp Vault, AWS Secrets Manager).
- Database-level encryption: enable `pgcrypto` extension + `ENCRYPTED COLUMN` for any future fields that must store secrets.
- TLS for DB connection via `sslmode=require` in `DATABASE_URL`.

### 4.6 PostgreSQL Extensions
- Enable `uuid-ossp` for UUID generation (if needed in future)
- Enable `pg_trgm` for fuzzy search on descriptions/titles (future)

---

## 5. Enum Types

| Enum | Values |
|---|---|
| `severity` | critical, high, medium, low, unknown |
| `findingsource` | trivy, grype |
| `imageregistry` | dockerhub, gcr, ecr, ghcr, gitlab, harbor, quay, other |
| `scanstatus` | pending, running, completed, failed, cancelled |
| `remediationstatus` | pending, analyzing, patching, building, verifying, pr_opened, completed, failed, skipped, requires_review |
| `remediationactiontype` | base_image_bump, dependency_update, config_change, package_removal, custom |
| `policytype` | severity_threshold, image_allowlist, image_denylist, auto_remediate, notification, compliance, retention |
| `policyaction` | block, alert, auto_fix, skip, require_approval, escalate |
| `auditeventtype` | scan_started, scan_completed, scan_failed, finding_created, finding_closed, remediation_started, remediation_completed, remediation_failed, policy_created, policy_updated, policy_violated, compliance_report_generated, config_changed, user_login, system_error |

---

## 6. Migration Workflow

```bash
# Set environment
export DATABASE_URL='postgresql+psycopg2://<user>:<password>@<host>:5432/<database>'

# Apply all pending migrations
alembic -c src/db/migrations/alembic.ini upgrade heads

# Generate a new migration after model changes
alembic -c src/db/migrations/alembic.ini revision --autogenerate -m "description"

# Roll back one migration
alembic -c src/db/migrations/alembic.ini downgrade -1
```

---

## 7. Repository Layer

Each domain has a repository class in `src/db/repositories.py`:

| Repository | Key Methods |
|---|---|
| `ImageRepository` | `create_or_get`, `list_active`, `deactivate`, `stats` |
| `ScanRepository` | `create`, `complete`, `fail`, `get_by_id`, `list_for_image` |
| `FindingRepository` | `upsert_finding`, `list_for_image`, `count_by_severity`, `mark_remediated`, `stats` |
| `SnapshotRepository` | `record_snapshot`, `trend_for_image` |
| `RemediationRepository` | `create`, `update_status`, `add_action`, `complete`, `list_for_image` |
| `ComplianceReportRepository` | `create`, `list_reports` |

All repository methods log audit events automatically for security-relevant operations.

---

## 8. Connection Management

| Context | Engine | Session |
|---|---|---|
| Celery workers (sync) | `sqlalchemy.create_engine()` with connection pool | `Session` via `get_session()` contextmanager |
| FastAPI (async) | `create_async_engine()` with async pool | `AsyncSession` via `get_async_session()` |

Both share the same pool configuration: `pool_size=20`, `max_overflow=10`, `pool_pre_ping=True`, `pool_recycle=3600`.

On connection: `SET timezone=UTC`, `SET work_mem='16MB'`, `SET statement_timeout=300000`.
