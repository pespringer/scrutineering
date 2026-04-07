# Scrutineering Documentation Index

Container Sentinel — Automated container vulnerability scanning, remediation planning, and policy enforcement.

## Table of Contents

### Getting Started
- [Quick Start](#quick-start) — Get running in 5 minutes
- [Setup Guide](setup-guide.md) — Full environment setup
- [Environment Variables](#environment-variables) — Configuration reference

### Architecture
- [Product Requirements Document](../docs/scrutineering.md) — Full PRD
- [System Architecture](#system-architecture) — Component overview and data flow
- [Scanning Engine](../docs/scanning-engine.md) — How scanning works
- [Database Schema](../docs/db-schema-design.md) — Data model details

### User Guides
- [Using the Dashboard](#using-the-dashboard) — Web UI reference
- [API Reference](#api-reference) — REST API endpoints
- [Running Scans](#running-scans) — Manual and scheduled scans
- [Remediation Workflows](#remediation-workflows) — From detection to PR
- [Risk Assessment](#risk-assessment) — Contextual scoring engine

### Testing & Validation
- [Testing Guide](#testing-guide) — How to test each component
- [Test Suite](#test-suite) — Running the full test suite
- [Harness Tools](#harness-tools) — Dry-run and verification harnesses
- [CI/CD Pipeline](#cicd-pipeline) — Automated testing in CI

### Operations
- [Deployment](#deployment) — Docker Compose and Kubernetes
- [Monitoring](#monitoring) — Prometheus, logging, health checks
- [Incident Response](../docs/operations/on-call-playbook.md) — Runbook
- [Production Readiness](../docs/operations/production-readiness-checklist.md) — Checklist

---

## Quick Start

```bash
# 1. Clone and configure
git clone https://github.com/pespringer/scrutineering && cd scrutineering
cp .env.example .env

# 2. Start all services
docker compose up --build -d

# 3. Run database migrations
docker compose exec app alembic -c alembic.ini upgrade head

# 4. Verify
curl http://localhost:3000/health
```

## API Reference

The Planner API (Node.js) runs on port 3000. All endpoints accept and return JSON.

### Health Check
```
GET /health
Response: { "status": "ok" }
```

### Create Remediation Plan
```
POST /v1/plans
Body: { "findings": [...], "dryRun": false }
```

### Create Pull Request Artifact
```
POST /v1/pull-requests
Body: { "plan": { ... }, "targetRepo": "..." }
```

### Evaluate CI Checks
```
POST /v1/ci/checks
Body: { "checks": [...], "requirements": { ... } }
```

### Evaluate Rollout
```
POST /v1/rollout/evaluate
Body: { "metrics": { ... }, "thresholds": { ... } }
```

### Dashboard API Endpoints
```
GET /api/scans          — List all scans
GET /api/images         — List scanned images
GET /api/images/:id     — Image detail with findings
GET /api/posture/summary — Security posture summary
GET /api/posture/trend   — Severity trend data
```

## Risk Assessment

The Contextual Risk Engine goes beyond raw CVSS scores by weighing:

| Factor | Weight | Description |
|--------|--------|-------------|
| Base CVSS | 25% | Raw vulnerability severity |
| EPSS | 15% | Exploit probability prediction |
| CISA KEV | 15% | Known exploited vulnerability flag |
| Network Exposure | 15% | How reachable is the container? |
| Data Sensitivity | 10% | What data does the container handle? |
| Container Risk | 10% | Escape/privilege escalation potential |
| Age | 5% | How long has it been unfixed? |
| Compliance | 5% | Regulatory framework violations |

## Testing Guide

See the [Testing section](#test-suite) below for complete instructions.

## Deployment

### Docker Compose (Development / Single Node)
```bash
docker compose up --build -d
```

### Kubernetes (Production)
```bash
kubectl apply -f k8s/infrastructure.yaml
kubectl apply -f k8s/planner-deployment.yaml
kubectl apply -f k8s/worker-deployment.yaml
kubectl apply -f k8s/celery-beat-deployment.yaml
kubectl apply -f k8s/services.yaml
```
