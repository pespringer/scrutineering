---
title: Database Schema Design
status: Draft
date: 2026-04-05
author: Apex (Coder)
---

# Database Schema Design — Container Sentinel

## 1. Overview

PostgreSQL 16 database with SQLAlchemy 2.0 ORM. All timestamps stored in UTC. The schema
is designed for **high-volume data ingest** (nightly scans of many images, each producing
hundreds of findings) while supporting fast dashboard queries and analytical trend lookups.

### Connection strings

| Environment | Variable | Format |
|---|---|---|
| Sync (Celery workers) | `DATABASE_URL` | `postgresql+psycopg2://user:pass@host:5432/db` |
| Async (FastAPI) | `ASYNC_DATABASE_URL` | `postgresql+asyncpg://user:pass@host:5432/db` |

### Design principles

- **Partition by time** — severity snapshots and runtime monitoring tables are candidates
  for declarative partitioning once volume warrants it (>10M rows).
- **Fingerprint-based de-duplication** — a deterministic fingerprint (hash of CVE +
  package + version) prevents duplicate rows when the same finding is reported across
  scanners or scan runs.
- **JSONB for variable payloads** — raw scanner output, policy rules, and event details
  are stored as JSONB to survive scanner version changes without schema modifications.
- **Cascade deletes** — when an image is removed, its findings, scans, and runtime data
  are cleaned up automatically.

---

## 2. Entity Diagram

```
images (1) ──< scans (N)             images (1) ──< scan_findings (N)
images (1) ──< raw_scan_results (N)  images (1) ──< remediations (N)
images (1) ──< severity_snapshots (N) remediations (1) ──< remediation_actions (N)
images (1) ──< container_runtime (N)  remediations (1) ──< scan_findings (back-ref)
images (1) ──< audit_log (N)         scan_findings (1) ──< audit_log (back-ref)
                                    images (1) ──< audit_log (N)

security_policies (1) ──< policy_evaluations (N)
scans (1) ──< policy_evaluations (N)
scan_findings (1) ──< policy_evaluations (N)
```

---

## 3. Tables

### 3.1 `images`

Container images tracked by Sentinel.

| Column | Type | Constraints | Default | Notes |
|---|---|---|---|---|
| id | BIGINT | PK, auto | | |
| registry | `image_registry` ENUM | NOT NULL | `dockerhub` | dockerhub, gcr, ecr, ghcr, gitlab, harbor, quay, other |
| repo_name | VARCHAR(512) | NOT NULL | | e.g. `library/nginx`, `myorg/myapp` |
| tag | VARCHAR(256) | NOT NULL | `latest` | |
| digest | VARCHAR(128) | nullable | | Immutable SHA256 digest |
| discovered_at | TIMESTAMP | NOT NULL | now() | First time Sentinel saw this image |
| last_scan_id | VARCHAR(64) | nullable | | Reference to most recent scan |
| last_scan_at | TIMESTAMP | nullable | | |
| active | BOOLEAN | NOT NULL | true | False = image no longer exists |
| labels | JSONB | NOT NULL | `{}` | User-assigned key/value pairs |

**Constraints:**
- Unique: `(registry, repo_name, tag)`
- Indexes: `registry`, `repo_name`, `tag`

---

### 3.2 `scans`

Individual scan executions. One row per image per scan run.

| Column | Type | Constraints | Default | Notes |
|---|---|---|---|---|
| id | BIGINT | PK, auto | | |
| scan_id | VARCHAR(64) | NOT NULL, UNIQUE | | UUID or timestamp-based ID |
| image_id | BIGINT | FK → images.id, ON DELETE CASCADE | | |
| started_at | TIMESTAMP | NOT NULL | now() | |
| completed_at | TIMESTAMP | nullable | | Set when scan finishes |
| duration_seconds | FLOAT | nullable | | |
| status | `scan_status` ENUM | NOT NULL | `pending` | pending, running, completed, failed, cancelled |
| total_findings | INT | NOT NULL | 0 | Updated on completion |
| critical_count | INT | NOT NULL | 0 | Count at completion |
| high_count | INT | NOT NULL | 0 | |
| medium_count | INT | NOT NULL | 0 | |
| low_count | INT | NOT NULL | 0 | |
| error_message | TEXT | nullable | | |
| scheduler_type | VARCHAR(32) | nullable | | `manual`, `scheduled`, `ci` |

**Indexes:** `image_id`, `status`, `started_at`, `(image_id, status)`

---

### 3.3 `scan_findings`

Deduplicated vulnerability findings. One row per unique (fingerprint, image).

| Column | Type | Constraints | Default | Notes |
|---|---|---|---|---|
| id | BIGINT | PK, auto | | |
| scan_id | VARCHAR(64) | nullable | | Scan where this finding was first seen in this cycle |
| image_id | BIGINT | FK → images.id, ON DELETE CASCADE | | |
| fingerprint | VARCHAR(128) | NOT NULL | | Deterministic: `hash(cve + pkg + version)` |
| package_name | VARCHAR(256) | NOT NULL | | |
| package_version | VARCHAR(64) | nullable | | |
| package_type | VARCHAR(64) | nullable | | os, npm, pip, go-module, etc. |
| cve_id | VARCHAR(32) | nullable | | |
| title | VARCHAR(1024) | NOT NULL | `""` | |
| description | TEXT | nullable | | |
| severity | `severity` ENUM | nullable | | critical, high, medium, low, unknown |
| source | `finding_source` ENUM | NOT NULL | | trivy, grype |
| scanner_version | VARCHAR(64) | nullable | | |
| fixed_version | VARCHAR(64) | nullable | | |
| fix_available | BOOLEAN | NOT NULL | false | Derived from fixed_version presence |
| first_seen | TIMESTAMP | NOT NULL | now() | |
| last_seen | TIMESTAMP | NOT NULL | now() | Updated each scan re-discovery |
| remediated | BOOLEAN | NOT NULL | false | |
| remediation_id | BIGINT | FK → remediations.id, ON DELETE SET NULL | nullable | |

**Constraints:**
- Unique: `(fingerprint, image_id)`
- Indexes: `image_id`, `severity`, `fingerprint`, `first_seen`, `remediated`, `(cve_id, image_id)`

---

### 3.4 `raw_scan_results`

Full scanner JSON output for audit and forensics.

| Column | Type | Constraints | Default | Notes |
|---|---|---|---|---|
| id | BIGINT | PK, auto | | |
| image_id | BIGINT | FK → images.id, ON DELETE CASCADE | | |
| scan_id | VARCHAR(64) | NOT NULL | | |
| scanner_source | `finding_source` ENUM | NOT NULL | | trivy, grype |
| raw_output | JSONB | NOT NULL | | Full scanner JSON |
| created_at | TIMESTAMP | NOT NULL | now() | |
| file_size_bytes | BIGINT | nullable | | |

**Indexes:** `image_id`, `scanner_source`, `scan_id`, `created_at`

---

### 3.5 `severity_snapshots`

Daily severity counts per image for trend charts.

| Column | Type | Constraints | Default | Notes |
|---|---|---|---|---|
| id | BIGINT | PK, auto | | |
| image_id | BIGINT | FK → images.id, ON DELETE CASCADE | | |
| snapshot_date | DATE | NOT NULL | | One row per image per day |
| critical_count | INT | NOT NULL | 0 | |
| high_count | INT | NOT NULL | 0 | |
| medium_count | INT | NOT NULL | 0 | |
| low_count | INT | NOT NULL | 0 | |
| total_open | INT | NOT NULL | 0 | Sum of non-remediated |
| newly_fixed | INT | NOT NULL | 0 | Count of findings closed since last snapshot |

**Constraints:**
- Unique: `(image_id, snapshot_date)`
- Indexes: `(image_id, snapshot_date)`, `snapshot_date`

---

### 3.6 `security_policies`

User-configurable policies controlling Sentinel behavior.

| Column | Type | Constraints | Default | Notes |
|---|---|---|---|---|
| id | BIGINT | PK, auto | | |
| name | VARCHAR(256) | NOT NULL | | |
| description | TEXT | nullable | | |
| policy_type | `policy_type` ENUM | NOT NULL | | severity_threshold, image_allowlist, image_denylist, auto_remediate, notification, compliance, retention |
| enabled | BOOLEAN | NOT NULL | true | |
| priority | INT | NOT NULL | 0 | Higher = evaluated first |
| rules | JSONB | NOT NULL | `{}` | Policy-specific rule definition |
| action | `policy_action` ENUM | NOT NULL | `alert` | block, alert, auto_fix, skip, require_approval, escalate |
| image_filters | JSONB | NOT NULL | `{}` | Scope: empty = all images |
| created_at | TIMESTAMP | NOT NULL | now() | |
| updated_at | TIMESTAMP | NOT NULL | now() | Auto-updated on change |
| created_by | VARCHAR(64) | nullable | | Agent or user ID |

**Indexes:** `policy_type`, `enabled`, `priority DESC`

---

### 3.7 `policy_evaluations`

Log of every policy evaluation against a scan or finding.

| Column | Type | Constraints | Default | Notes |
|---|---|---|---|---|
| id | BIGINT | PK, auto | | |
| policy_id | BIGINT | FK → security_policies.id, ON DELETE CASCADE | | |
| scan_id | VARCHAR(64) | nullable | | |
| finding_id | BIGINT | FK → scan_findings.id, ON DELETE SET NULL | nullable | |
| evaluated_at | TIMESTAMP | NOT NULL | now() | |
| violated | BOOLEAN | NOT NULL | false | Did this policy trigger? |
| detail | JSONB | NOT NULL | `{}` | What matched, what was evaluated |
| action_taken | `policy_action` ENUM | nullable | | Resulting action |

**Indexes:** `policy_id`, `scan_id`, `violated`

---

### 3.8 `remediations`

Tracking of automated remediation efforts.

| Column | Type | Constraints | Default | Notes |
|---|---|---|---|---|
| id | BIGINT | PK, auto | | |
| image_id | BIGINT | FK → images.id, ON DELETE CASCADE | | |
| status | `remediation_status` ENUM | NOT NULL | `pending` | full lifecycle |
| scan_id | VARCHAR(64) | nullable | | Scan that triggered this |
| finding_count | INT | NOT NULL | 0 | Number of CVEs targeted |
| target_severities | JSONB | NOT NULL | `{}` | Which severities to target |
| pr_url | VARCHAR(2048) | nullable | | URL of created PR/MR |
| pr_number | INT | nullable | | |
| branch_name | VARCHAR(512) | nullable | | |
| verified | BOOLEAN | NOT NULL | false | Did re-scan confirm fix? |
| verification_findings_before | INT | NOT NULL | 0 | Finding count pre-remediation |
| verification_findings_after | INT | NOT NULL | 0 | Finding count post-remediation |
| created_at | TIMESTAMP | NOT NULL | now() | |
| started_at | TIMESTAMP | nullable | | |
| completed_at | TIMESTAMP | nullable | | |
| error_message | TEXT | nullable | | |

**Indexes:** `status`, `image_id`, `created_at`

---

### 3.9 `remediation_actions`

Individual steps within a remediation (e.g., bumping a base image tag).

| Column | Type | Constraints | Default | Notes |
|---|---|---|---|---|
| id | BIGINT | PK, auto | | |
| remediation_id | BIGINT | FK → remediations.id, ON DELETE CASCADE | | |
| action_type | `remediation_action_type` ENUM | NOT NULL | | base_image_bump, dependency_update, config_change, package_removal, custom |
| file_path | VARCHAR(1024) | nullable | | Path that was changed |
| before_value | VARCHAR(1024) | nullable | | Value before the change |
| after_value | VARCHAR(1024) | nullable | | Value after the change |
| success | BOOLEAN | NOT NULL | false | |
| detail | JSONB | NOT NULL | `{}` | Action-specific metadata |
| created_at | TIMESTAMP | NOT NULL | now() | |

**Indexes:** `remediation_id`, `action_type`

---

### 3.10 `compliance_reports`

Metadata for generated compliance reports.

| Column | Type | Constraints | Default | Notes |
|---|---|---|---|---|
| id | BIGINT | PK, auto | | |
| title | VARCHAR(512) | NOT NULL | | |
| report_format | VARCHAR(16) | NOT NULL | | `pdf`, `html`, `json` |
| scope | JSONB | NOT NULL | `{}` | Which images / date range |
| generated_at | TIMESTAMP | NOT NULL | now() | |
| file_path | VARCHAR(2048) | nullable | | Path to generated file |
| summary | JSONB | NOT NULL | `{}` | High-level metrics |
| generated_by | VARCHAR(64) | nullable | | |

**Indexes:** `report_format`, `generated_at`

---

### 3.11 `audit_log`

Append-only audit trail for all security and system events.

| Column | Type | Constraints | Default | Notes |
|---|---|---|---|---|
| id | BIGINT | PK, auto | | |
| timestamp | TIMESTAMP | NOT NULL | now() | |
| event_type | `audit_event_type` ENUM | NOT NULL | | Full set of event types |
| entity_type | VARCHAR(64) | nullable | | `scan`, `finding`, `remediation`, `policy` |
| entity_id | VARCHAR(128) | nullable | | Reference to the entity |
| image_id | BIGINT | FK → images.id, ON DELETE SET NULL | nullable | |
| detail | JSONB | NOT NULL | `{}` | Event-specific data |
| actor | VARCHAR(64) | nullable | | Who/what triggered |
| actor_kind | VARCHAR(16) | nullable | | `agent`, `scheduler`, `user`, `system` |

**Indexes:** `event_type`, `timestamp`, `image_id`, `(entity_type, entity_id)`

---

### 3.12 `container_runtime`

Runtime behavior monitoring for active containers.

| Column | Type | Constraints | Default | Notes |
|---|---|---|---|---|
| id | BIGINT | PK, auto | | |
| container_id | VARCHAR(128) | NOT NULL | | Docker container ID |
| image_id | BIGINT | FK → images.id, ON DELETE CASCADE | | |
| timestamp | TIMESTAMP | NOT NULL | now() | |
| event_type | VARCHAR(64) | NOT NULL | | network_connection, file_write, process_spawn, etc. |
| severity | `severity` ENUM | nullable | | |
| detail | JSONB | NOT NULL | `{}` | Event-specific payload |
| source | VARCHAR(128) | nullable | | `docker_events`, `falco`, etc. |

**Indexes:** `container_id`, `image_id`, `timestamp`, `event_type`

---

## 4. Enumerations

| Enum name | Values |
|---|---|
| `image_registry` | dockerhub, gcr, ecr, ghcr, gitlab, harbor, quay, other |
| `severity` | critical, high, medium, low, unknown |
| `scan_status` | pending, running, completed, failed, cancelled |
| `finding_source` | trivy, grype |
| `remediation_status` | pending, analyzing, patching, building, verifying, pr_opened, completed, failed, skipped, requires_review |
| `remediation_action_type` | base_image_bump, dependency_update, config_change, package_removal, custom |
| `policy_type` | severity_threshold, image_allowlist, image_denylist, auto_remediate, notification, compliance, retention |
| `policy_action` | block, alert, auto_fix, skip, require_approval, escalate |
| `audit_event_type` | scan_started, scan_completed, scan_failed, finding_created, finding_closed, remediation_started, remediation_completed, remediation_failed, policy_created, policy_updated, policy_violated, compliance_report_generated, config_changed, user_login, system_error |

---

## 5. Migration Strategy

- **Alembic** manages all schema migrations.
- First migration (`001_initial`) creates the full baseline schema above.
- Future migrations add columns, indexes, or tables — never drop data without a separate
  data-migration step.
- The `alembic.ini` and migration scripts live in `src/db/alembic/`.

### Running migrations

```bash
# Development — create all tables from models
ALEMBIC=1 alembic upgrade head

# Create a new migration after model changes
alembic revision --autogenerate -m "description"

# Apply
alembic upgrade head

# Rollback one step
alembic downgrade -1
```

---

## 6. Data Retention Policies

The following retention rules should be enforced by a periodic Celery task
(`src/scan/tasks.py`):

| Table | Retention | Strategy |
|---|---|---|
| `raw_scan_results` | 90 days | Delete rows older than 90 days |
| `severity_snapshots` | 365 days | Keep forever (used for trend charts) |
| `container_runtime` | 30 days | Delete rows older than 30 days |
| `policy_evaluations` | 180 days | Delete rows older than 180 days |
| `audit_log` | 365 days | Keep minimum 1 year for compliance |
| `scan_findings` | Indefinite (remediated flagged) | Keep all; prune only if image was deleted |
| `scans` | 365 days | Keep metadata, delete raw only |
