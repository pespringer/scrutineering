# Product Requirements Document: Container Sentinel

**Automated Container Security Scanning with Intelligent Remediation**

| | |
|---|---|
| **Version** | 1.0 |
| **Date** | April 2026 |
| **Author** | Patrick Springer |
| **Status** | Draft |

---

## 1. Executive Summary

Container Sentinel is a self-hosted container security platform that combines dual-engine vulnerability scanning (Trivy and Grype) with an intelligent auto-remediation engine. Unlike existing tools that merely report CVE lists, Sentinel closes the loop by analyzing Dockerfiles, generating patched versions, verifying builds, and opening pull requests — reducing mean time to remediation from days to minutes.

The product targets two audiences: individual DevOps practitioners and home lab operators who want to secure their container infrastructure at no cost (open-source core), and small-to-mid-size development teams who need automated remediation workflows with compliance reporting (paid Pro tier).

**Mission:** Eliminate the gap between finding container vulnerabilities and fixing them.

Container Sentinel is designed to be built and used internally first, providing immediate value to the author's own infrastructure before being offered commercially.

---

## 2. Problem Statement

### Current Landscape

Container vulnerability scanning tools are mature and largely commoditized. Trivy and Grype are free, fast, and accurate. However, the output of these tools is a CVE list — often hundreds of entries — that lands on a developer's desk with no actionable next step.

### Key Pain Points

- **Alert fatigue:** First scans commonly surface 100–200+ findings. Without severity filtering, de-duplication, and trend tracking, teams tune out.
- **No cross-scanner correlation:** Teams running multiple scanners get duplicate CVEs with no unified view. Manual de-duplication is tedious and error-prone.
- **Remediation is entirely manual:** Identifying which Dockerfile layer introduced the vulnerability, determining the fix (base image bump, package pin, dependency update), applying the change, rebuilding, re-scanning, and opening a PR — this loop takes 4–12+ days on average.
- **No closed-loop verification:** Even when a fix is applied, most teams don't rebuild and re-scan to confirm the CVE is resolved before merging.
- **Home lab blind spot:** Self-hosted container environments often run dozens of images with zero scanning. Existing commercial tools are priced for enterprise, not individuals.

### The Gap

The market has strong scanners and strong CI/CD platforms, but nothing that connects them with an intelligent remediation engine. Container Sentinel fills this gap.

---

## 3. Vision and Goals

### Product Vision

A self-hosted, opinionated container security platform that makes vulnerability remediation automatic, verified, and auditable.

### Strategic Goals

| Goal | Metric | Target |
|------|--------|--------|
| Reduce mean time to remediation | Avg hours from detection to merged fix | < 4 hours for auto-fixable CVEs |
| Achieve meaningful auto-fix rate | % of fixable CVEs auto-remediated | > 50% within 6 months |
| Provide unified security posture | Single-pane-of-glass adoption | 100% of scanned images visible in dashboard |
| Build a monetizable product | Monthly recurring revenue | $1,000 MRR within 12 months of launch |
| Dogfood on own infrastructure | Internal deployment coverage | All home lab containers scanned from day 1 |

---

## 4. Target Users

### Persona 1: Home Lab Operator

**Profile:** Experienced IT professional or enthusiast running 10–50+ containers on Proxmox/Docker. Reads r/selfhosted and r/homelab. Cares about security but doesn't have time to scan and patch manually.

- **Needs:** Automated scanning on a schedule, a dashboard showing what's vulnerable, and clear guidance on which images need attention.
- **Willingness to pay:** $0 for core scanning (they'll self-host). $10–15/month for auto-remediation and compliance reports if the product proves its value.

### Persona 2: Small Team Lead / DevSecOps Engineer

**Profile:** Engineering lead or security engineer at a 5–30 person dev team. Responsible for container security in CI/CD pipelines. Uses GitLab or GitHub. Reports to leadership on security posture.

- **Needs:** Auto-remediation that opens PRs they can review, compliance-ready reports for SOC2/audit, and Slack alerts on critical findings.
- **Willingness to pay:** $49–99/month per team. This replaces hours of manual triage work weekly.

### Persona 3: Solo Developer Shipping Containers

**Profile:** Indie hacker or freelancer deploying 2–5 containerized services. May not have a security background. Wants to "do the right thing" without becoming a security expert.

- **Needs:** One-command scanning, plain-language explanations of what's wrong, and auto-fix with minimal configuration.
- **Willingness to pay:** $19/month for a "set and forget" solution.

---

## 5. Features and Requirements

### Core Features (Open Source)

#### F1: Dual-Engine Scanning

Run Trivy and Grype against container images to maximize CVE coverage. Each scanner has different database sources and detection heuristics; running both catches findings that either alone would miss.

| Requirement | Priority | Details |
|-------------|----------|---------|
| Trivy integration | P0 | Async CLI wrapper, JSON output parsing, severity filtering |
| Grype integration | P0 | Async CLI wrapper, JSON output parsing, artifact type mapping |
| Cross-scanner de-duplication | P0 | Fingerprint-based (CVE + package + version), keep most complete finding |
| Scan scheduling | P0 | Cron-based via Celery Beat, configurable per-image or global |
| Auto-discovery | P1 | Detect running containers via Docker socket, apply include/exclude filters |
| Registry scanning | P2 | Connect to private registries, scan all tags or latest only |

#### F2: Findings Database and Tracking

Persist all findings in PostgreSQL with full history. Track when vulnerabilities first appeared, when they were resolved, and how long they remained open.

| Requirement | Priority | Details |
|-------------|----------|---------|
| Finding persistence | P0 | SQLAlchemy models with image, scan, finding, and remediation tables |
| Severity trend tracking | P0 | Daily snapshots of severity counts per image for trend charts |
| First-seen / last-seen | P0 | Track lifecycle of each CVE per image |
| SBOM generation | P1 | Syft integration for SPDX and CycloneDX output |

#### F3: Dashboard

Web-based UI providing a single pane of glass for security posture. Designed for quick triage, not deep analysis.

| Requirement | Priority | Details |
|-------------|----------|---------|
| Posture overview | P0 | Total images, finding counts by severity, fixable count |
| Severity trend chart | P0 | Line chart showing CRITICAL/HIGH/MEDIUM/LOW over time |
| Image detail view | P0 | Per-image findings list, sortable and filterable |
| Remediation queue | P1 | Pending, in-progress, and completed remediation attempts |
| Scan history | P1 | Timeline of scans with success/failure status |

#### F4: Notifications

Alert on new critical findings or scan failures via webhook, Slack, or email. Configurable severity thresholds.

### Pro Features (Paid)

#### F5: Remediation Engine

The core differentiator. Automatically analyzes vulnerabilities, generates patches, and opens pull requests.

| Requirement | Priority | Details |
|-------------|----------|---------|
| Dockerfile layer analysis | P0 | Map each CVE to the FROM, RUN, or COPY instruction that introduced it |
| Base image bump | P0 | Check registry for patched versions of the same base image tag |
| Dependency updates | P0 | Update lockfiles for npm, pip, go mod, and Cargo |
| Build verification | P0 | Rebuild patched image, re-scan to confirm fix, fail gracefully |
| PR/MR creation | P0 | Open pull requests via GitHub/GitLab API with descriptive title, diff, and labels |
| Dry-run mode | P1 | Generate patches without pushing, for review before enabling auto-fix |
| Auto-merge | P2 | Optionally merge PRs automatically if all CI checks pass |

#### F6: Policy Engine

Define rules governing auto-remediation behavior: which severities to auto-fix, which images to skip, approval gates for production images, and escalation paths for unfixable CVEs.

#### F7: Compliance Reporting

Generate PDF/HTML reports suitable for SOC2 audits, security reviews, or management dashboards. Include scan coverage, open findings, remediation rates, and mean time to fix.

---

## 6. Architecture

### System Components

| Component | Technology | Purpose |
|-----------|-----------|---------|
| API Server | Python 3.12, FastAPI | REST API, dashboard backend, scan/remediation triggers |
| Worker | Celery | Async scan execution, remediation tasks, build verification |
| Scheduler | Celery Beat | Cron-based scan scheduling |
| Database | PostgreSQL 16 | Findings storage, audit trail, trend data |
| Cache / Broker | Redis 7 | Celery message broker and result backend |
| Scanner: Trivy | Trivy CLI (binary) | OS and language package vulnerability scanning |
| Scanner: Grype | Grype CLI (binary) | Cross-reference vulnerability scanning |
| SBOM Generator | Syft CLI (binary) | Software bill of materials in SPDX/CycloneDX |
| Git Integration | GitHub/GitLab MCP Servers | PR creation, branch management via existing MCP infra |
| Dashboard | Next.js 15, React 18 | Web UI for posture view, triage, and config |
| Reverse Proxy | Traefik | TLS termination, routing via Docker labels |

### Deployment Model

Container Sentinel is distributed as a Docker Compose stack with Traefik labels pre-configured. The Dockerfile uses a multi-stage build: a scanner stage installs Trivy, Grype, and Syft binaries, and the final stages produce lean API and worker images. The Docker socket is mounted read-only for container auto-discovery.

For production deployments, all configuration is driven by a single YAML file with environment variable expansion for secrets (tokens, database credentials). Redis and PostgreSQL are included in the Compose stack but can be pointed at external instances.

### Data Flow

1. Celery Beat triggers a scan task based on the configured cron schedule.
2. The worker discovers target images (auto-discovery via Docker socket or explicit config).
3. For each image, Trivy and Grype run in parallel (async subprocess calls).
4. JSON outputs are parsed into normalized VulnerabilityFinding objects.
5. The orchestrator de-duplicates findings across scanners using a fingerprint hash.
6. Unique findings are persisted to PostgreSQL with full metadata.
7. If remediation is enabled, eligible findings are queued for analysis.
8. The remediation engine reads the Dockerfile, maps CVEs to layers, and generates patches.
9. Patched images are rebuilt and re-scanned to verify the fix.
10. Verified patches are pushed as branches and PRs are opened via Git integration.
11. Notifications fire on critical findings, failed scans, or completed remediations.

---

## 7. Phased Delivery Roadmap

### Phase 1: Scanner Core (Weeks 1–4)

**Goal:** Scan all home lab containers on a schedule and view results in a dashboard.

- Trivy and Grype async wrappers with JSON parsing
- Scan orchestrator with cross-scanner de-duplication
- PostgreSQL models and Alembic migrations
- Celery worker + Beat for scheduled scans
- Docker auto-discovery via socket mount
- FastAPI endpoints: trigger scan, list images, list findings, dashboard stats
- Basic React dashboard: posture overview, severity trend chart, findings table
- Docker Compose stack with Traefik labels

*Milestone: All home lab containers scanned nightly, results visible in dashboard.*

### Phase 2: Remediation Engine (Weeks 5–8)

**Goal:** Automatically fix base image and dependency vulnerabilities with build verification.

- Dockerfile analyzer: parse FROM, RUN, COPY to map CVEs to layers
- Base image remediator: query registries for patched tags
- Dependency remediator: update lockfiles for npm, pip, go, Cargo
- Build verification: rebuild patched image, re-scan, pass/fail
- Patch diff generation for review
- Dry-run mode (generate patches, don't push)

*Milestone: First auto-generated patch verified and ready for review.*

### Phase 3: Git Integration and PR Automation (Weeks 9–12)

**Goal:** Automatically open PRs with verified fixes on GitLab and GitHub.

- Integration with existing GitHub and GitLab MCP servers
- Branch creation with configurable naming patterns
- PR/MR creation with descriptive body (CVEs fixed, diff, scan results)
- Label and assignee assignment
- Remediation status tracking (pending → PR opened → merged)
- Slack notifications on PR creation and merge

*Milestone: First end-to-end auto-remediation: scan → patch → build → PR → merge.*

### Phase 4: Policy Engine and Compliance (Weeks 13–16)

**Goal:** Enable configurable policies and generate compliance-ready reports.

- Policy definitions: severity thresholds, image allow/deny lists, approval gates
- Compliance report generation (PDF/HTML) with scan coverage and remediation metrics
- SBOM export in SPDX and CycloneDX formats
- Audit log for all scan and remediation activity

*Milestone: Generate a SOC2-ready container security report on demand.*

### Phase 5: Multi-Registry and Team Features (Weeks 17–20)

**Goal:** Support multiple registries, team collaboration, and self-service onboarding.

- Multi-registry connections (Docker Hub, GitLab Registry, Harbor, ECR)
- Team management: user roles, image ownership, notification routing
- API keys for CI/CD pipeline integration
- Public marketing site and documentation

*Milestone: First external paying customer onboarded.*

---

## 8. Monetization Strategy

### Open-Core Model

The core scanning, de-duplication, dashboard, and notification features are open source under AGPL-3.0. The remediation engine, policy engine, and compliance reporting are source-available under a commercial license.

### Pricing Tiers

| Tier | Price | Includes |
|------|-------|----------|
| Community | Free | Dual-engine scanning, de-duplication, dashboard, Slack alerts, unlimited images |
| Solo | $19/month | Everything in Community + auto-remediation for up to 20 images, dry-run mode |
| Team | $49/month | Everything in Solo + unlimited images, PR automation, policy engine, compliance reports |
| Business | $99/month | Everything in Team + multi-registry, team management, API keys, priority support |

### Revenue Projections (Conservative)

| Month | Community Users | Paid Users | MRR |
|-------|----------------|------------|-----|
| Month 3 | 50 | 5 | $145 |
| Month 6 | 200 | 20 | $680 |
| Month 9 | 500 | 50 | $1,750 |
| Month 12 | 1,000 | 100 | $3,500 |

These projections assume organic growth through r/selfhosted, r/homelab, Hacker News, and build-in-public content on X/Twitter. No paid acquisition budget.

---

## 9. Technology Stack

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| Language | Python 3.12 | Strong async support, ecosystem for security tooling, author expertise |
| API Framework | FastAPI | High performance, auto-generated OpenAPI docs, Pydantic integration |
| ORM | SQLAlchemy 2.0 (async) | Mature, well-documented, Alembic for migrations |
| Database | PostgreSQL 16 | JSONB for raw scan output, robust indexing, proven at scale |
| Task Queue | Celery + Redis | Reliable async task execution, cron scheduling via Beat |
| Scanners | Trivy, Grype, Syft | Industry-standard open-source tools, JSON output, active maintenance |
| Frontend | Next.js 15, React 18, TypeScript | Consistent with existing projects, SSR for dashboard performance |
| Git Integration | FastMCP (Python) | Leverages existing GitHub and GitLab MCP servers already built |
| Containerization | Docker, Docker Compose | Multi-stage build, scanner binaries baked into image |
| Reverse Proxy | Traefik | Docker label-based config, wildcard SSL via Cloudflare DNS challenge |
| Validation | Pydantic v2 | Config parsing, API schemas, consistent with MCP server patterns |

---

## 10. Risks and Mitigations

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| Auto-remediation breaks builds | HIGH | MEDIUM | Build verification step: re-scan before PR. Dry-run mode as default. |
| Scanner output format changes | MEDIUM | LOW | Pin scanner versions in Dockerfile. Version-specific parsers with fallback. |
| Low adoption / hard to market | HIGH | MEDIUM | Build-in-public on X. Dogfood extensively. Open-source core for trust. |
| Scope creep delays Phase 1 | MEDIUM | HIGH | Strict phase gating. Phase 1 is scanner + dashboard only. No remediation. |
| Docker socket access is a security risk | MEDIUM | LOW | Read-only mount. Document risk. Offer socket-less mode (explicit image list). |
| Competing with free tools | MEDIUM | MEDIUM | Free tools don't remediate. Differentiate on the closed loop, not scanning. |

---

## 11. Success Metrics

### Phase 1 (Internal)

- 100% of home lab containers scanned nightly
- Dashboard loads in under 2 seconds
- Zero false-positive duplicates in cross-scanner de-duplication
- Scan completes in under 5 minutes for 30 images

### Phase 2–3 (Remediation)

- Auto-remediation success rate > 35% of fixable CVEs
- Build verification catches 100% of breaking patches
- Mean time from scan to PR opened < 30 minutes
- Zero PRs merged that re-introduce the same CVE

### Phase 4–5 (Commercial)

- 20+ GitHub stars within 3 months of open-source release
- 5+ paid users within 3 months of Pro launch
- $1,000 MRR within 12 months
- Net Promoter Score > 40 from user surveys

---

## 12. Appendix

### A. Competitive Landscape

| Tool | Scanning | De-dup | Auto-Remediation | Self-Hosted | Price |
|------|----------|--------|-----------------|-------------|-------|
| Trivy (standalone) | Yes | No | No | Yes | Free |
| Grype (standalone) | Yes | No | No | Yes | Free |
| Docker Scout | Yes | N/A | Recommendations only | No | Free tier / paid |
| Snyk Container | Yes | N/A | PR for base image | No | $25+/dev/month |
| GitLab Container Scanning | Yes | N/A | Limited (Dockerfile) | Partial | Ultimate tier |
| Aikido | Yes | Yes | Fix PRs | No | Paid |
| **Container Sentinel** | **Trivy + Grype** | **Yes** | **Full (build-verify-PR)** | **Yes** | **Free core / $19–99** |

### B. Glossary

- **CVE:** Common Vulnerabilities and Exposures. A standardized identifier for a known security vulnerability.
- **SBOM:** Software Bill of Materials. A machine-readable inventory of all components in a software artifact.
- **SPDX / CycloneDX:** Standard formats for representing SBOMs.
- **MCP:** Model Context Protocol. A protocol for connecting AI models to external tools and services.
- **MTTR:** Mean Time to Remediation. Average time from vulnerability detection to fix deployment.

### C. References

- Trivy documentation: https://aquasecurity.github.io/trivy
- Grype documentation: https://github.com/anchore/grype
- Syft documentation: https://github.com/anchore/syft
- FastMCP: https://github.com/jlowin/fastmcp
- OpenSSF Scorecard: https://scorecard.dev

