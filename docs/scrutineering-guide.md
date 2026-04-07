# Scrutineering — Application Guide

## What Is Scrutineering?

Scrutineering (aka Container Sentinel) is an automated container vulnerability scanning and remediation platform. It continuously scans container images for security vulnerabilities, assesses their contextual risk, generates prioritized remediation plans, creates pull request artifacts, and manages staged rollouts — all while tracking compliance with security frameworks.

## Quick Start

### Prerequisites
- Docker 24+ and Docker Compose v2
- Python 3.12+ (for scanner workers)
- Node.js 20+ (for planner API and dashboard)
- PostgreSQL 16 (provided by docker compose)
- Redis 7 (provided by docker compose)

### Running the Full Stack

```bash
cd scrutineering
cp .env.example .env
docker compose up --build -d
```

This starts:
- **Planner API** (port 3000) — REST endpoints for remediation planning, PR generation
- **PostgreSQL** — metadata, scan results, findings persistence
- **Redis** — message broker for Celery worker tasks

### Running the Dashboard

```bash
cd dashboard
npm install
npm run dev
```

The dashboard is available at `http://localhost:3000` (or the port Next.js reports).

## Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│                    UI Layer                          │
│              Next.js Dashboard                       │
│  (Posture, Scan History, Image Detail, Findings)    │
└─────────────────────┬───────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────┐
│                   API Layer                          │
│        Node.js Planner Service                       │
│  POST /v1/plans       — Remediation plans           │
│  POST /v1/pull-requests  — PR artifact generation   │
│  POST /v1/ci/checks     — CI/CD check evaluation    │
│  POST /v1/rollout/evaluate — Rollout decisions      │
└─────────────────────┬───────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────┐
│                 Worker Layer                         │
│            Python Celery Workers                     │
│  run_scan(image_name)       — Trivy + Grype scan    │
│  run_batch_scan(images[])   — Batch scanning        │
└─────────────────────┬───────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────┐
│                Data Layer                            │
│         PostgreSQL + Risk Assessment                 │
│  • Scans, findings, images, raw results             │
│  • Risk scoring, compliance checking                │
│  • MITRE ATT&CK mapping, threat intel               │
│  • False positive detection                         │
└─────────────────────────────────────────────────────┘
```

## Key Components

### Scanner Engine (`src/scan/`)

The scanning engine runs Trivy and Grype container scanners in parallel, deduplicates findings, and persists results to PostgreSQL.

- **`scanners/trivy.py`** — Trivy scanner adapter with CVSS extraction
- **`scanners/grype.py`** — Grype scanner adapter
- **`tasks.py`** — Celery tasks (`run_scan`, `run_batch_scan`)
- **`registry.py`** — Multi-registry auth (Docker Hub, ECR, GCR, GHCR, Harbor, GitLab)
- **`scan_service.py`** — High-level scan orchestration with risk scoring
- **`utils/dedup.py`** — Cross-scanner deduplication
- **`utils/db.py`** — Database persistence layer

**Usage:**
```python
from src.scan.scan_service import ScanService

service = ScanService()
result = await service.scan("nginx:latest", scanners=["trivy", "grype"])
# Returns: scan_id, status, findings count, risk_score, errors, etc.
```

### Risk Assessment Engine (`src/risk/`)

Evaluates vulnerabilities contextually — not just raw CVSS scores, but considering deployment context, threat intelligence, compliance impact, and attack chain analysis.

- **`engine.py`** — Central orchestrator (`RiskAssessmentEngine.assess()`)
- **`threat_intel.py`** — EPSS, CISA KEV, threat actor, ransomware data
- **`mitre.py`** — MITRE ATT&CK technique mapping
- **`compliance.py`** — NIST CSF, PCI DSS, SOC 2, HIPAA, GDPR checks
- **`impact.py`** — Blast radius, lateral movement, container escape analysis
- **`false_positive.py`** — Automated false positive detection

**Usage:**
```python
from src.risk.engine import RiskAssessmentEngine
from src.risk.models import VulnerabilityInput, ContainerContext, NetworkExposure, DataSensitivity

engine = RiskAssessmentEngine()
vuln = VulnerabilityInput(
    cve_id="CVE-2024-3094",
    package_name="xz",
    package_version="5.4.1",
    cvss_score=10.0,
    container_context=ContainerContext(
        network_exposure=NetworkExposure.PUBLIC_DIRECT,
        data_sensitivity=DataSensitivity.REGULATED,
    ),
)
result = engine.assess(vuln)
# result.contextual_risk_score, result.risk_level, result.mitre_mappings,
# result.compliance_findings, result.false_positive, etc.
```

### Planner Service (`src/planner/`)

Node.js REST API for external integration:

| Endpoint | Description |
|---|---|
| `POST /v1/plans` | Generate remediation plans from scan findings |
| `POST /v1/pull-requests` | Generate PR artifacts for fix proposals |
| `POST /v1/ci/checks` | Evaluate CI/CD security gates |
| `POST /v1/rollout/evaluate` | Make rollout/block decisions |
| `GET /health` | Health check |

### CI Integration (`src/ci/`)

Integrates with GitHub Actions and GitLab CI to evaluate security policies during pipelines. Supports blocking merges based on severity thresholds.

### PR Generator (`src/pr-generator/`)

Generates structured pull request artifacts with fix details, severity assessments, and compliance impact summaries for each proposed remediation.

### Dry-Run Harness (`src/harness/`)

Tests the remediation pipeline end-to-end without making real changes. Validates scan → plan → PR → CI → rollout flow.

### Rollout Controller (`src/staged-rollout/`)

Makes staged rollout decisions based on scan results, policy compliance, verification status, and risk scores.

### Verification Harness (`src/verification/`)

Validates that remediated images pass all security gates before production deployment.

### Database Schema (`src/db/`)

PostgreSQL models (SQLAlchemy) covering:
- **Images** — tracked container images with registry, repo, tag
- **Scans** — individual scan executions with timing and counters
- **ScanFindings** — deduplicated vulnerability records with fingerprints
- **RawScanResults** — raw JSON scanner output for audit
- **SeveritySnapshots** — daily trend data
- **SecurityPolicies** — policy definitions with JSON rules
- **PolicyEvaluations** — policy violation log
- **Remediations** — remediation lifecycle tracking
- **AuditLog** — append-only audit trail
- **ContainerRuntime** — runtime behavior monitoring

Migrations managed with Alembic: `alembic upgrade head`

## Running Tests

### Python (Scanner + Risk)
```bash
cd scrutineering
pytest tests/ -v
```
Tests cover:
- `test_scan_engine.py` — Trivy parser, Grype parser, registry detection, risk scoring, dedup
- `test_risk_engine.py` — Full risk assessment, MITRE mapping, threat intel, compliance, impact analysis, false positive detection

### Node.js (Planner + Services)
```bash
find src -name "*.test.mjs" -exec node --test {} \;
```

### Dashboard
```bash
cd dashboard
npx next build    # TypeScript + build verification
npm test          # (when added)
```

## Running the Dashboard

The Next.js dashboard provides a visual interface for:
- **Security Posture** — Total scanned images, severity counts, fixable vulns, last scan time
- **Severity Trend Chart** — Line chart showing severity counts over time (recharts)
- **Image List** — All scanned images with finding counts
- **Image Detail** — Sortable/filterable findings table per image with CVE links
- **Scan History** — Timeline of recent scans with status, duration, and severity breakdown

```bash
cd dashboard
npm run build    # Production build
npm start        # Production server
# OR
npm run dev      # Development with hot reload
```

## Configuration

### Environment Variables (`.env`)
See `.env.example` for all variables. Key ones:

| Variable | Description |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string |
| `REDIS_URL` | Redis connection URL |
| `CELERY_BROKER_URL` | Celery task broker |
| `TRIVY_SEVERITY` | Comma-separated severity filter (default: CRITICAL,HIGH) |
| `GRYPE_SEVERITY_THRESHOLD` | Minimum severity for Grype |
| `SCANNER_TIMEOUT` | Seconds before scanner timeout (default: 1800) |
| `SCHEDULE_CRON_SCAN` | Cron schedule for periodic scans |
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to GCR service account key |
| `GITHUB_TOKEN` | Token for GHCR access |

### Kubernetes Deployment

Manifests in `k8s/`:
```bash
kubectl apply -f k8s/infrastructure.yaml     # ConfigMap, Secret, Postgres, Redis
kubectl apply -f k8s/planner-deployment.yaml
kubectl apply -f k8s/worker-deployment.yaml
kubectl apply -f k8s/celery-beat-deployment.yaml
kubectl apply -f k8s/services.yaml
```

### Monitoring

- **Prometheus** config in `monitoring/prometheus-config.yaml`
- **Fluentbit** logging config in `monitoring/logging.yaml`
- Planner exposes `/metrics` endpoint for Prometheus scraping

## Security Policies

Policies are defined in JSON and validated against schemas in `schemas/policy-contract/`.

Types:
- `severity_threshold` — Block if findings exceed severity limits
- `image_allowlist` / `image_denylist` — Restrict allowed/blocked images
- `auto_remediate` — Auto-generate fixes for specific severities
- `notification` — Alert on certain conditions
- `compliance` — Enforce compliance framework requirements
- `retention` — Scan result retention rules

Example:
```json
{
  "type": "severity_threshold",
  "rules": {
    "max_critical": 0,
    "max_high": 5,
    "action": "block"
  }
}
```

## Compliance Frameworks

The risk assessment engine checks vulnerabilities against:

- **NIST CSF** — DE.CM, PR.AC, PR.DS, RS.RP, ID.RA controls
- **PCI DSS v4.0** — 1.3, 2.2, 6.2, 6.4, 6.5, 10.1, 11.2, 11.3
- **SOC 2** — CC6.1, CC6.6, CC7.1, CC7.2, CC8.1
- **HIPAA** — 164.312 access, audit, integrity, authentication, transmission
- **GDPR** — Articles 32 (security), 33 (breach notification), 35 (DPIA)

## Operations

See `docs/operations/` for runbooks:
- `on-call-playbook.md` — Incident response guide
- `production-readiness-checklist.md` — Before deploying to production
- `weekly-security-outcome-report.md` — Weekly executive report template
- `cto-checkpoint-2026-04-05.md` — Executive status updates

