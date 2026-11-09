# Container Image Scanning Engine — Design Doc

## Overview

The scanning engine provides continuous container image vulnerability analysis using multiple scanners (Trivy + Grype), with deduplication, CVSS-based risk scoring, and multi-registry support.

## Architecture

```
Image Scan Request
       |
       v
┌──────────────────┐
│  ScanService     │  ← Entry point: registry detection + auth
└────────┬─────────┘
         |
    ┌────┴────┐
    v         v
┌──────┐  ┌───────┐
│Trivy │  │ Grype │  ← Run concurrently, isolated errors
└──┬───┘  └───┬───┘
   v          v
┌──────────────────┐
│ Deduplication    │  ← Hash-based fingerprint merge
└────────┬─────────┘
         |
         v
┌──────────────────┐
│ PostgreSQL Store │  ← Images, scans, findings, raw results
└──────────────────┘
```

## Supported Registries

| Registry      | Auth Method                    | Env Vars Required              |
|---------------|--------------------------------|-------------------------------|
| Docker Hub    | Username/password              | DOCKERHUB_USERNAME, DOCKERHUB_PASSWORD |
| AWS ECR       | AWS CLI get-login-password     | AWS credentials configured     |
| GCR           | Service account key JSON       | GOOGLE_APPLICATION_CREDENTIALS |
| GHCR          | GitHub personal access token   | GITHUB_TOKEN                   |
| Harbor        | Harbor username/password       | harbor_url, username, password |
| GitLab        | CI job token or personal token | GITLAB_TOKEN or CI_JOB_TOKEN   |

## Scanner Adapters

### TrivyScanner

- CLI wrapper around `trivy image --format json`
- Extracts CVSS scores from NVD, Red Hat, Debian, Alpine, GHSA, OSV vendors
- Configurable severity filtering
- Private registry auth via TRIVY_USERNAME/TRIVY_PASSWORD env vars
- Timeout handling (default 600s)

### GrypeScanner

- CLI wrapper around `grype -o json`
- Maps Grype severity to canonical enum
- Extracts fix versions from vulnerability data
- Isolates failures (won't crash the pipeline)

## Deduplication Strategy

Fingerprint: `sha256(CVE_ID | package_name | package_version)[:64]`

- Same finding from multiple scanners → single record with merged sources
- Scan without CVE (package advisories) → fingerprinted by package+version
- New scanner run → updates `last_seen` timestamp on existing findings

## Risk Scoring

CVSS-based weighted risk score:
- **max_cvss**: Highest CVSS v3 score across all vendors
- **risk_level**: Derived from critical/high/medium/low finding counts + max_cvss
  - `critical`: any CRITICAL finding or CVSS >= 9.0
  - `high`: any HIGH finding or CVSS >= 7.0
  - `medium`: any MEDIUM finding or CVSS >= 4.0
  - `low`: everything else
- **weighted_score**: 0–100 normalized severity-weighted score

## Performance

| Scenario                 | Target                        |
|--------------------------|-------------------------------|
| Single image scan        | < 5 minutes (both scanners)   |
| Batch scan (500 images)  | < 30 minutes (4 concurrent)   |
| Concurrent scanners      | Trivy + Grype run in parallel |

Concurrent scanning is achieved via:
1. `ScanService` runs scanner coroutines concurrently per image.
2. Celery tasks use a bounded thread pool because each task bridges its async scanner adapter through a dedicated event loop.
3. Results are collected in configured scanner order, so reports remain deterministic even when completion order differs.
4. Batch scans use `asyncio.Semaphore` for controlled image-level concurrency.

## Execution Modes

### Direct (Python API)

```python
from src.scan.scan_service import ScanService

service = ScanService()
result = await service.scan("nginx:latest", scanners=["trivy", "grype"])
```

### Celery Worker

```python
from src.scan.tasks import run_scan

result = run_scan.delay(image_name="nginx:latest")
```

### Sequential (for environments without Celery)

The scan_service.py module can run directly without Celery for testing or lightweight deployments.
