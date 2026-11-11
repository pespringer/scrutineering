# Testing Guide — Scrutineering

This document covers how to test every component of the Scrutineering platform.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Python Test Suite](#python-test-suite)
3. [Node.js Test Suite](#nodejs-test-suite)
4. [Harness Tools](#harness-tools)
5. [Manual API Testing](#manual-api-testing)
6. [End-to-End Testing](#end-to-end-testing)
7. [Policy Contract Validation](#policy-contract-validation)
8. [CI/CD Pipeline Tests](#cicd-pipeline-tests)

---

## Prerequisites

Before running tests, ensure:

### Node.js
```bash
npm install
```

### Python
```bash
pip install -r requirements.txt
```

### Database (for migration tests)
Either use Docker Compose or a local PostgreSQL instance.

---

## Python Test Suite

The Python tests cover the scanning engine, risk assessment, analytics, forensics, and runtime modules.

### Run All Tests
```bash
pytest tests/ -v
```

### Run Individual Test Files

**Scanning engine** (Trivy/Grype parsing, dedup, registry detection):
```bash
pytest tests/test_scan_engine.py -v
```

**Risk assessment engine** (contextual scoring, MITRE mapping, compliance):
```bash
pytest tests/test_risk_engine.py -v
```

**Analytics** (trends, compliance reporting, posture summaries):
```bash
pytest tests/test_analytics.py -v
```

**Forensics** (audit trails, SIEM integration, root cause analysis):
```bash
pytest tests/test_forensics.py -v
```

**Celery tasks** (scan task execution, error handling):
```bash
pytest tests/test_tasks.py -v
```

**Runtime** (container monitoring, eBPF agent, runtime analysis):
```bash
pytest tests/test_runtime.py -v
```

### Test Coverage
```bash
pytest tests/ --cov=src --cov-report=html
# Open htmlcov/index.html in a browser
```

### What Each Test Module Covers

#### test_scan_engine.py
- Trivy JSON output parsing (single vuln, no vulns, multiple results)
- Grype JSON output parsing (severity mapping, fix version extraction)
- Cross-scanner deduplication (fingerprint matching, source merging)
- Registry detection (Docker Hub, GHCR, ECR, GCR, Harbor, GitLab)
- Risk score computation (CVSS-based, severity counts)
- Concurrent batch scanning (asyncio semaphore, error isolation)

#### test_risk_engine.py
- VulnerabilityInput validation and defaults
- RiskAssessmentEngine single assessment
- EPSS and CISA KEV integration
- MITRE ATT&CK mapping
- Compliance framework checks (NIST, PCI, SOC 2, HIPAA, GDPR)
- False positive detection heuristics
- Contextual risk score computation and breakdown
- Batch assessment with priority sorting
- Recommendation generation logic

#### test_analytics.py
- Security posture summary generation
- Severity trend tracking over time
- Compliance reporting for audit
- Remediation outcome tracking
- Notification routing based on severity

#### test_forensics.py
- Audit trail generation
- SIEM integration patterns
- Root cause analysis workflows
- Incident timeline reconstruction
- Security snapshot capture
- Forensic report generation

#### test_tasks.py
- Celery scan task execution
- Error handling and retry logic
- Task result serialization
- Scheduler integration

#### test_runtime.py
- Container monitoring (Docker and containerd)
- eBPF agent behavior
- Runtime analysis of suspicious behavior
- Alert generation and routing
- Runtime event correlation

---

## Node.js Test Suite

The Node.js tests cover the remediation planner, PR generator, CI integration, verification harness, and staged rollout.

### Run All Node.js Tests
```bash
find src -name "*.test.mjs" -exec node --test {} +
```

### Run Individual Tests

**Remediation planner** (Dockerfile analysis, patch generation):
```bash
node --test src/planner/remediation-planner.test.mjs
```

**PR generator** (branch naming, PR body generation):
```bash
node --test src/pr-generator/pr-generator.test.mjs
```

**CI integration** (check evaluation, provider detection):
```bash
node --test src/ci/ci-integration.test.mjs
```

**Telemetry** (SLO/SLI reporting, weekly summaries):
```bash
node --test src/telemetry/remediation-telemetry.test.mjs
```

**Staged rollout** (canary analysis, promotion logic):
```bash
node --test src/rollout/staged-rollout.test.mjs
```

**Verification harness** (policy verification, build confirm):
```bash
node --test src/verification/verification-harness.test.mjs
```

### Watch Mode (Development)
```bash
node --watch --test src/planner/remediation-planner.test.mjs
```

### What Each Test File Covers

#### remediation-planner.test.mjs
- Plan creation from vulnerability findings
- Dry-run mode (generate plans without actions)
- Base image bump detection and patch generation
- Dependency update recommendations
- Fix prioritization by severity

#### pr-generator.test.mjs
- Pull request title generation
- PR body with CVE details and diff
- Branch naming conventions
- Label and assignee assignment
- Multi-CVE PR consolidation

#### ci-integration.test.mjs
- CI check evaluation logic
- Provider-specific behavior (GitHub vs GitLab)
- Required checks enforcement
- Pass/fail/neutral decision handling

#### staged-rollout.test.mjs
- Canary deployment analysis
- Promotion/demotion decisions
- Error budget tracking
- Automatic rollback triggers

#### verification-harness.test.mjs
- Post-remediation scan verification
- Policy contract compliance checking
- Build verification pass/fail logic

---

## Harness Tools

Harness tools are standalone scripts that simulate real-world scenarios for validation without making external changes.

### Remediation Dry-Run Harness

Simulates the full remediation pipeline without making actual changes. Tests the planner, PR generator, and build verification flow end-to-end using pre-seeded fixtures.

```bash
node scripts/run-remediation-dry-run-harness.mjs
```

**What it does:**
1. Loads pre-seeded vulnerability findings from fixtures/harness/remediation-dry-run/fixtures.json
2. Runs them through the remediation planner
3. Generates PR artifacts for simulated fixes
4. Produces a summary report at fixtures/harness/remediation-dry-run/summary.json

**Useful when:**
- Validating the remediation pipeline after code changes
- Demonstrating the auto-remediation flow to stakeholders
- Testing new remediation strategies without touching real repos

### Verification Harness

Validates that the policy engine, verification, and compliance checks work correctly.

```bash
node scripts/run-verification-harness.mjs
```

**What it does:**
1. Generates a simulated verification result
2. Checks against the policy contract schema
3. Writes a verification report to fixtures/verification/verification-result.json

### Security Outcome Report

Generates a weekly remediation outcome report from seeded fixture data.

```bash
node scripts/generate-security-outcome-report.mjs
```

### Debrief Compliance Report

Generates a compliance report for hiring/interview debriefs.

```bash
node scripts/generate-debrief-compliance-report.mjs
```

---

## Manual API Testing

### Health Check
```bash
curl http://localhost:3000/health
# Expected: {"status":"ok"}
```

### Create a Remediation Plan
```bash
curl -X POST http://localhost:3000/v1/plans \
  -H "Content-Type: application/json" \
  -d '{"findings":[{"cve":"CVE-2024-1234","package":"openssl","version":"1.1.1","fixedVersion":"1.1.2","severity":"HIGH"}]}'
```

### Create a Pull Request Artifact
```bash
curl -X POST http://localhost:3000/v1/pull-requests \
  -H "Content-Type: application/json" \
  -d '{"plan":{"findings":[...],"actions":[]},"targetRepo":"org/repo"}'
```

### Evaluate CI Checks
```bash
curl -X POST http://localhost:3000/v1/ci/checks \
  -H "Content-Type: application/json" \
  -d '{"checks":[{"name":"build","status":"success"}],"requirements":["build"]}'
```

### Evaluate Rollout Decision
```bash
curl -X POST http://localhost:3000/v1/rollout/evaluate \
  -H "Content-Type: application/json" \
  -d '{"metrics":{"errorRate":0.01},"thresholds":{"maxErrorRate":0.05}}'
```

### Dashboard API
```bash
# List scans
curl http://localhost:3000/api/scans

# Posture summary
curl http://localhost:3000/api/posture/summary

# Severity trend
curl http://localhost:3000/api/posture/trend

# Image detail
curl http://localhost:3000/api/images/<image-id>
```

---

## End-to-End Testing

### Full Stack Test (Docker Compose)

1. Start all services:
```bash
docker compose up --build -d
```

2. Apply migrations from the API container:
```bash
docker compose exec api alembic -c src/db/migrations/alembic.ini upgrade heads
```

3. Verify planner is healthy:
```bash
curl http://localhost:3000/health
```

4. Run the dry-run harness:
```bash
docker compose exec app node scripts/run-remediation-dry-run-harness.mjs
```

5. Run the verification harness:
```bash
docker compose exec app node scripts/run-verification-harness.mjs
```

6. Check the dashboard at http://localhost:3000/dashboard

### Testing with Real Scanners

To test with actual Trivy/Grype (not mocked):

```bash
# Start the worker service with scanner binaries
docker compose up celery-worker -d

# Trigger a scan via the API or Celery task
# The worker will download Trivy/Grype and scan target images
```

---

## Policy Contract Validation

The policy contract defines rules for auto-remediation behavior. Validate against the JSON schema:

```bash
# Validate all example contracts
node scripts/validate-policy-contract.mjs

# The schema is at schemas/policy-contract/v1.schema.json
# Valid examples are in schemas/policy-contract/examples/
```

### Policy Contract Schema

The schema validates:
- Required fields: actor, audit metadata, actions
- Valid risk levels: critical, high, medium, low, informational
- No unrecognized fields
- Proper structure for exception rules

See `schemas/policy-contract/` for the full schema and examples.

---

## CI/CD Pipeline Tests

The CI pipeline runs automatically on every push.

### Pipeline Stages (`.github/workflows/ci.yml`)

1. **Lint** — ESLint for Node.js, flake8/black for Python
2. **Node.js Tests** — All .test.mjs files via `node --test`
3. **Python Tests** — pytest on the full test suite
4. **Build** — Docker image build (on main merge)
5. **Security Scan** — Trivy scan of built images

### Pipeline Releases (`.github/workflows/release.yml`)

On tag push (e.g., `v1.0.0`):
1. Builds production Docker images
2. Scans images with Trivy
3. Pushes to container registry
4. Creates GitHub release with artifacts

### Trigger Manually
```bash
# You can also trigger via GitHub CLI
gh workflow run ci.yml
gh workflow run release.yml
```

---

## Fixture Data

Pre-built test fixtures are in the `fixtures/` directory:

| Directory | Purpose |
|-----------|---------|
| `fixtures/harness/remediation-dry-run/` | Seeded findings for dry-run testing |
| `fixtures/hiring/` | Debrief events for hiring calibration |
| `fixtures/planner/` | Seeded findings for planner testing |
| `fixtures/pr-generator/` | Pre-generated PR artifacts for comparison |
| `fixtures/telemetry/` | Sample weekly remediation data |
| `fixtures/verification/` | Expected verification results |

These fixtures provide consistent, deterministic test data so results are reproducible across runs.

---

## Troubleshooting Tests

### Python tests fail with import errors
Ensure you are in the project root and the package is on the Python path:
```bash
PYTHONPATH=. pytest tests/ -v
```

### Node.js tests fail with module not found
Install dependencies first:
```bash
npm install
```

### Celery worker won't connect to Redis
Check Redis is running and the connection string matches:
```bash
redis-cli ping
# Should return PONG

docker compose logs redis
```

### Database migration fails
Ensure PostgreSQL is running and the DATABASE_URL is correct:
```bash
docker compose exec postgres pg_isready
```
