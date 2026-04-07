# Scrutineering — Testing Guide

## Overview

This document covers how to test each component of the Scrutineering application, including unit tests, integration tests, and end-to-end validation.

## Test Architecture

### Python Components (Scanner + Risk Engine)

All Python tests use **pytest** and are in `tests/`:

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_scan_engine.py -v
pytest tests/test_risk_engine.py -v

# Run with coverage
pytest tests/ --cov=src --cov-report=html
```

#### Scan Engine Tests (`test_scan_engine.py`) — 22 tests

| Test Class | Tests | Coverage |
|---|---|---|
| `TestTrivyParser` | 6 tests | Scan output parsing, CVSS extraction, multi-result, missing fields, invalid JSON |
| `TestGrypeParser` | 2 tests | Single match parsing, empty results |
| `TestRegistryDetection` | 7 tests | Docker Hub, ECR, GHCR, GCR, Harbor, private registry patterns |
| `TestRiskScore` | 5 tests | Critical/high/low scoring, empty input, weighted score capping |
| `TestFingerprint` | 2 tests | Deterministic hashing, CVE vs package differentiation |

#### Risk Engine Tests (`test_risk_engine.py`) — 25 tests

| Test Class | Tests | Coverage |
|---|---|---|
| `TestRiskAssessmentEngine` | 3 tests | Full assessment, low-priority, batch assessment |
| `TestMitreMapping` | 5 tests | Log4Shell, PwnKit, keyword matching, unknown CVE, package heuristics |
| `TestThreatIntel` | 5 tests | KEV detection, non-exploited, invalid CVE, EPSS high score, XZ backdoor |
| `TestComplianceChecker` | 3 tests | Public-facing, internal non-sensitive, ransomware triggers |
| `TestImpactAnalyzer` | 3 tests | Container escape, contained vuln, K8s blast radius |
| `TestFalsePositiveDetection` | 6 tests | Build-time pkg, kernel pkg, already fixed, no FP, non-runtime path, wontfix |

### Node.js Components (Planner + Services)

Tests use Node's built-in `node:test` runner. Files are co-located with `*.test.mjs` extension.

```bash
# Run all .test.mjs files
find src -name "*.test.mjs" -exec node --test {} \;

# Run specific test
node --test src/planner/remediation-planner.test.mjs
```

Test modules:
| Module | Tests | Coverage |
|---|---|---|
| `remediation-planner.test.mjs` | Plan generation from findings, priority sorting, fixable detection |
| `ci-integration.test.mjs` | CI check evaluation, policy enforcement, block/allow decisions |
| `staged-rollout.test.mjs` | Rollout decision logic based on scan results and policies |
| `pr-generator.test.mjs` | PR artifact generation with severity summaries |
| `harness/remediation-dry-run-harness.test.mjs` | End-to-end pipeline validation |
| `telemetry/remediation-telemetry.test.mjs` | Metrics collection and reporting |

### Dashboard (Next.js)

```bash
cd dashboard
npx next build    # TypeScript check + static page generation
```

The build process includes:
- TypeScript type checking
- Tailwind CSS compilation
- Static page prerendering

## Integration Testing

### Testing the Scan Pipeline

```bash
# With Docker Compose running:
docker compose exec app node scripts/run-remediation-dry-run-harness.mjs

# Verify findings persisted:
docker compose exec postgres psql -U scrutineering -d scrutineering -c \
  "SELECT COUNT(*) FROM scan_findings;"

# Verify scan records:
docker compose exec postgres psql -U scrutineering -d scrutineering -c \
  "SELECT scan_id, image_id, status, total_findings FROM scans ORDER BY started_at DESC;"
```

### Testing the API

```bash
# Health check
curl http://localhost:3000/health

# Generate remediation plan
curl -X POST http://localhost:3000/v1/plans \
  -H "Content-Type: application/json" \
  -d '{"findings": [{"cve_id": "CVE-2024-0727", "severity": "CRITICAL", "package_name": "openssl"}]}'

# Generate PR artifact
curl -X POST http://localhost:3000/v1/pull-requests \
  -H "Content-Type: application/json" \
  -d '{"plan": {"actions": [{"type": "base_image_bump", "current": "alpine:3.18", "target": "alpine:3.19"}]}}'

# CI check evaluation
curl -X POST http://localhost:3000/v1/ci/checks \
  -H "Content-Type: application/json" \
  -d '{"findings": [{"severity": "HIGH", "fixed_version": "2.0"}]}'
```

### Testing the Dashboard

```bash
cd dashboard
npm run dev

# Visit http://localhost:3000/dashboard and verify:
# - Posture stat cards render with data
# - Severity trend chart renders
# - Image list shows images with finding counts
# - Clicking an image navigates to detail view
# - Findings table is sortable and filterable
# - Visit http://localhost:3000/scans for scan history timeline
```

## Security Testing

### Testing the Compliance Engine

```python
from src.risk.engine import RiskAssessmentEngine
from src.risk.models import VulnerabilityInput, ContainerContext, DataSensitivity, ComplianceFramework

engine = RiskAssessmentEngine()

# Test GDPR violation
vuln = VulnerabilityInput(
    cve_id="CVE-2021-44228",
    package_name="log4j",
    cvss_score=10.0,
    container_context=ContainerContext(
        data_sensitivity=DataSensitivity.REGULATED,
    ),
    compliance_scope=[ComplianceFramework.GDPR],
)
result = engine.assess(vuln)
print(f"GDPR violations: {[c.control_id for c in result.compliance_findings if c.violated]}")
```

### Testing False Positive Detection

```python
from src.risk.false_positive import FalsePositiveDetector

detector = FalsePositiveDetector()

# Should detect as false positive (kernel package in container)
result = detector.assess(
    package_name="linux-headers",
    description="Kernel vulnerability CVE-2024-xxxxx",
)
assert result.is_false_positive
print(f"Confidence: {result.confidence:.0%}")
print(f"Reasons: {result.reasons}")
```

### Testing Threat Intelligence

```python
from src.risk.threat_intel import ThreatIntelClient

client = ThreatIntelClient()

# Log4Shell should be in KEV with high EPSS
intel = client.lookup("CVE-2021-44228")
assert intel.known_exploited_vulnerability
assert intel.epss_score > 0.9
assert intel.exploit_status.value == "in_the_wild"
```

## Running the Full E2E Flow

1. **Scan**: `src/scan/tasks.py` — Run scan against an image
2. **Assess**: `src/risk/engine.py` — Score vulnerabilities
3. **Plan**: `src/planner/remediation-planner.mjs` — Generate remediation plan
4. **Validate**: `src/harness/remediation-dry-run-harness.mjs` — Dry run validation
5. **Generate PR**: `src/pr-generator/pr-generator.mjs` — Create PR artifact
6. **Evaluate CI**: `src/ci/ci-integration.mjs` — Check CI gates
7. **Rollout**: `src/rollout/staged-rollout.mjs` — Make deployment decision

Each step can be tested independently using the scripts in `scripts/`:

```bash
node scripts/run-remediation-dry-run-harness.mjs
node scripts/run-verification-harness.mjs
node scripts/validate-policy-contract.mjs
node scripts/generate-staging-pr-artifact.mjs
node scripts/generate-security-outcome-report.mjs
node scripts/generate-debrief-compliance-report.mjs
node scripts/test_adversarial.mjs
```

## Troubleshooting

### Tests fail with import errors
```bash
cd /home/claw/paperclip/scrutineering
pip install -r requirements.txt
pytest tests/
```

### Dashboard build fails
```bash
cd dashboard
rm -rf .next
npm install
npx next build
```

### Database migration issues
```bash
alembic -c alembic.ini current
alembic -c alembic.ini upgrade head
```
