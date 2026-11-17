# Scrutineering Reset Plan

Status: proposed · Written 2026-11-15 · Owner: Patrick Springer

This plan replaces `docs/meaningful-milestone-plan.md` and `docs/upgrade-roadmap.md`.
Until it is complete, **no work outside this plan gets merged**.

## The product, in one loop

```text
push or discover an image → scan (Trivy + Grype) → track findings per image
→ propose a fix → build a patched image → rescan it → open a PR → mark resolved
```

Everything in the repo either serves this loop or gets removed. Things removed
here can return later (Phase 6), but only after the loop works end to end and
has a test that proves it.

## Ground rules (add these to AGENTS.md in Phase 0)

1. The **golden-path test** (Phase 3) is the definition of "working". A change
   that breaks it does not merge, even if every other test passes.
2. No new top-level module, service, env var, or npm/Make target unless the
   phase you are working on calls for it.
3. One status field per entity. Event tables are history, never the source of
   truth for state.
4. The client never asserts facts the server can check (no `evidence_verified`,
   `findings_before`, or digests posted from the browser).
5. Formatting: no line over 120 characters. Run Prettier on `dashboard/`, and
   Ruff (format and lint) on `src/` and `tests/`.
6. Docs describe the current system only. History belongs in git, not in the README.

---

## Phase 0 — Safety net (size: S)

- [x] Tag the current state of `main` as `pre-reset-2026-11` and push the tag.
      Everything cut below can be recovered from this tag.
- [x] Add the ground rules above to `AGENTS.md`.
- [x] Add `remediator,security-operator` to `DASHBOARD_DEFAULT_ROLES` in
      `.env.example`, so a fresh install can open the remediation pages.
- [x] Add Prettier (`dashboard/.prettierrc.json`) and Ruff (`ruff.toml`) configs,
      plus an advisory `format-check` CI job. Don't reformat yet; that happens in
      Phase 3, which also makes the check blocking.

**Done when:** the tag exists, AGENTS.md has the rules, and CI runs the advisory format check.

---

## Phase 1 — Cut (size: M)

Work in the order below. Each group is one PR that leaves `pytest`, the
dashboard build, and `docker compose up` working.

### 1a. Node control plane (unused by the product)

The dashboard only calls the Python API (`/api/dashboard/*`). Nothing calls the
Node planner.

| Remove | Notes |
|---|---|
| `src/planner/`, `src/auth/`, `src/ci/`, `src/pr-generator/`, `src/harness/`, `src/verification/`, `src/rollout/` | The Node service and its libraries. Python already has its own GitHub/GitLab publisher. |
| `src/telemetry/remediation-telemetry*.mjs`, `src/remediation/post-merge-policy.mjs`, `test_adversarial.mjs` | Node leftovers. |
| `Dockerfile` (planner image), `k8s/planner-deployment.yaml` | |
| `docker-compose.yml` → `app` service | Also remove `app` from the dashboard's `depends_on`. |
| `dashboard/src/lib/api.ts` | Dead file that points at `:3000`; nothing imports it. |
| `schemas/policy-contract/`, `schemas/evidence/`, `fixtures/planner/`, `fixtures/harness/`, `fixtures/pr-generator/` | Only the Node validators used these. |
| Root `package.json`, `package-lock.json`, `node_modules/` | The root keeps no Node code. Replace the useful scripts with a `Makefile` (see 1e). |

**Also update:** `.github/workflows/ci.yml` (drop the `test-node` job and the
planner image builds), `README.md`, `.dockerignore`.

**Status: done.** Changes beyond the table above:
- **Makefile now, not in 1e.** A minimal `Makefile` arrived early, because
  removing the root `package.json` removed the npm scripts that CI called. 1e
  only has to trim it.
- **Repository checks kept.** The doc-link, deployment, frontend and release
  validators stayed, and their tests moved from `src/verification/` to
  `scripts/tests/`.
- **Removed alongside the planner:**
  - its k8s Service and PodDisruptionBudget, and its keys in the ConfigMap
  - the planner image in `release.yml`
  - `OIDC_ISSUER`, `OIDC_AUDIENCE` and the `PLANNER_*` settings in `.env.example`
  - Node-only fixtures (`fixtures/hiring`, `telemetry`, `verification`)
  - the 7 docs that only described removed code (planner API, Node auth,
    dry-run harness, evidence contract, rollback drill)
- **Retargeted:** Prometheus now scrapes the API's `/metrics`, and the CI Trivy
  job scans the API image.
- **Compatibility:** Compose still accepts `PLANNER_API_KEY` as a fallback for
  `PYTHON_API_KEY`, so existing `.env` files keep working.

### 1b. Python subsystems the UI never calls

| Remove | Notes |
|---|---|
| `src/risk/` | Not imported anywhere outside itself. |
| `src/forensics/` | Remove its router from `src/api/app.py`. |
| `src/runtime/` **except** `docker_monitor.py` and `containerd_monitor.py` | Move those two into `src/scan/discovery/`; `src/scan/runtime_discovery.py` uses them. Remove the runtime router (`/api/runtime`), the eBPF agent, alerts, managed delivery, and replay. |
| `src/platform/` | The "readiness" and "maturity" modules take booleans and return "ready". Move the 5 helpers that are actually used (`bounded_output`, `guard_changed_files`, `classify_validation_failure`, `RetentionPolicy`, `parse_retry_after`) into `src/remediation/limits.py`. |
| `src/analytics/api.py`, `compliance.py`, `notifications.py`, `trends.py`, `posture.py`, `__init__.py` re-exports | The dashboard uses only `dashboard_api.py`. |
| `src/scan/api.py` (`/api/v1`), `scan_service.py`, `db_provider.py`, `provenance.py` | A second scan API that the UI doesn't use. |
| `src/db/alembic/` | Abandoned migration tree. The live one is `src/db/migrations/`. |
| `src/scan/utils/db.py` → module-level `engine`, `init_db`, `get_session` | Creates a second database engine at import. Keep `persist_findings`; it already uses `src.db.connection`. |
| `/release-health`, `/production-operations` routes in `dashboard_api.py` | They depend on `src/platform`. |

**Status: done.** Changes beyond the table above:
- **New discovery package.** The container-listing methods moved into
  `src/scan/discovery/` (`docker.py`, `containerd.py`), not whole monitor files,
  because the monitors depended on the eBPF event model. The listing code now
  has tests (`tests/test_scan_discovery.py`); before, it had none.
- **Moved earlier from 1c:**
  - the dashboard Operations page, its proxy route and nav links (they called
    the removed `/production-operations` route)
  - `src/remediation/backup.py` (unused, and depended on `src/platform`)
  - the backup-freshness beat task
- **Removed with `scan_service.py`:** `src/scan/circuit_breaker.py` and
  `src/scan/cache.py`. Only `ScanService` used them; the worker uses
  `redis_cache.py`.
- **Removed from `scripts/`:** the 14 Python scripts that imported removed
  modules, earlier than 1e.
- **Removed docs:** the 5 docs about removed code (scan data API v1, image
  identity, audit integrity, runtime backpressure, platform hardening).
- **Findings that moved to Phase 2.** The retry, circuit-breaker and
  immutable-identity code only ever ran in the unused `ScanService`, never in
  the Celery worker. The README claims about `REQUIRE_IMMUTABLE_SCAN_IDENTITY`
  and registry credentials were therefore false and have been corrected.

### 1c. Remediation side systems

These exist to support deployment evidence, alert delivery and provider
recovery, which come after a loop that doesn't work yet.

| Remove from `src/remediation/` | |
|---|---|
| `alert_contracts.py`, `alert_delivery.py`, `alert_governance.py`, `alert_tasks.py` | Alert delivery |
| `deployment_collectors.py`, `deployment_config.py`, `deployment_evidence.py`, `deployment_tasks.py` | Deployment observation |
| `evidence_archive.py`, `evidence_export.py`, `evidence_retention.py`, `retention_tasks.py` | Evidence export and retention |
| `recovery.py`, `recovery_tasks.py`, `reconciliation.py`, `reconciliation_tasks.py` | Provider recovery and stale reconciliation |
| `provider_status.py`, `provider_diagnostics.py`, `provider_hardening.py`, `provider_resilience.py` | Provider diagnostics |
| `audit_export.py`, `backup.py`, `chaos.py`, `concurrency.py`, `execution_resilience.py`, `lifecycle.py`, `post_merge_coordinator.py`, `rollback.py`, `parsers.py` | Unused or in-memory only |
| `approval.py` | Replaced by a plain role-gated `POST /approve` (the browser currently issues the token and posts it straight back). |

**Keep, for now:** `worker.py`, `executor.py`, `adapter.py`, `worktree.py`,
`edits.py`, `validation.py`, `publisher.py`, `publication.py`,
`provider_publishers.py`, `provider_callbacks.py`, `provider_auth.py`,
`post_merge.py`, `post_merge_tasks.py`, `events.py`, `state_machine.py`.
Phase 4 rewrites most of these.

**Dashboard API routes to remove** (`src/analytics/dashboard_api.py`):
`approval-token`, `publication-plan`, `post-merge/verify`, all
`/publications/{id}/recovery*`, `/publications/{id}/evidence`,
`/publications/{id}/deployment-evidence`, top-level `/deployment-evidence`,
`/collect-deployment-observation`,
`/deployment-observation/preflight*`, `/alert-evidence`, `/evidence-export`,
`/remediations/alert-deliveries*`, `/recovery-bulk-status`,
`/publications/reconciliation*`, `/provider-credentials/health`,
`/provider-diagnostics`.

**Dashboard pages and components to remove:** `app/operations/`,
`app/remediations/alerts/`, `components/RecoveryControls.tsx`, the matching
`app/api/**` proxy routes, and `lib/seed.ts` along with `DASHBOARD_DEMO_MODE`.

**Celery beat entries to remove** (`src/scan/celery_app.py`): stale-publication
reconciliation, recovery polling, alert delivery, evidence retention, backup
freshness, and scan retention reporting. Keep scheduled scans and runtime
discovery.

**Workflows to remove:** `.github/workflows/release.yml`,
`remediation-evidence.yml`, `deployment-evidence.yml`.

**Status: done.** Changes beyond the lists above:
- **Kept, not removed:**
  - `rollback.py`: the publication plan and the post-merge `rollback_required`
    path still use it.
  - `.github/workflows/remediation-evidence.yml`: it produces the signed
    evidence envelope the worker requires before executing a remediation. It
    goes in Phase 4, when the evidence gate is replaced by build-and-rescan.
- **Approval:** `POST /approve` now takes no body. It requires the
  `security-operator` role and records the caller as approver. The executor's
  unused approval-token check was removed.
- **Also removed:**
  - `POST /remediations/{id}/publish`, which accepted `evidence_verified` from
    the client (ground rule 4). The worker already publishes when publication
    is enabled.
  - scan retention reporting (`src/scan/retention*.py`) with its beat entry
  - the release-config validator
  - unused metric functions, with the Prometheus rules and Grafana panels
    that used them
  - 31 settings no code reads. Among them are `GITHUB_ALLOWED_REPOSITORIES`,
    `GITLAB_ALLOWED_PROJECTS` and `REQUIRE_BRANCH_PROTECTION`, which the README
    presented as publication safeguards; the real allowlist is
    `REMEDIATION_ALLOWED_REPOSITORIES`.
- **Renamed:** `k8s/deployment-observation-rbac.yaml` became
  `k8s/worker-service-account.yaml`, since only the worker ServiceAccount is left.
- **Fixed:** the remediation queue's status filter offered values that aren't
  real statuses (`approved`, `executing`, `blocked`), which made the page show a
  misleading role error.

### 1d. Database

Tables with no remaining code after 1a–1c: `raw_scan_results`,
`security_policies`, `policy_evaluations`, `compliance_reports`,
`audit_chain_anchors`, `forensic_snapshots`, `forensic_network_flows`,
`container_runtimes`, `remediation_release_evidence`,
`remediation_recovery_requests`, `remediation_alert_evidence`,
`remediation_alert_deliveries`, `remediation_reconciliation_runs`.

**Decided (D2): squash.** The 28 migrations were replaced by one baseline,
`src/db/migrations/versions/0001_baseline.py`.

**Status: done.**
- **Removed:** the 13 tables above from the models and baseline, plus three dead
  `remediations` columns (`approval_token_hash`, `verification_findings_before`,
  `verification_findings_after`).
- **Model bug fixed:** the models declared a `char_length()` CHECK on the
  `images.registry` enum column. Postgres rejects that, so the models could not
  create their own schema. The models and the old migration chain had drifted
  apart.
- **Drift protection:** the baseline was autogenerated from the models.
  `alembic check` reports no differences on Postgres, and downgrade removes
  every table and enum type. `tests/test_migration_baseline.py` upgrades a
  SQLite database and fails on any drift between migrations and models.
  `env.py` now accepts a caller-supplied connection so that test can run.
- **Also removed:** the root `alembic.ini` (a duplicate), the four tests that
  checked individual old revisions, and `scripts/validate-migration-matrix.py`.

**Upgrading an existing installation.** The new baseline can't be applied on
top of the old chain, so recreate the database. This deletes scans, findings,
remediations and audit history. Registry images are kept.

```bash
docker compose exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB"' | gzip > pre-squash.sql.gz  # optional
docker compose down
docker volume rm scrutineering_pgdata
make up && make migrate
```

### 1e. Scripts, docs, tests

- **Scripts:** delete all of `scripts/` except `backup-postgres.py`. Add a
  `Makefile` with `up`, `down`, `migrate`, `test`, `e2e`, `fmt`, `lint`.
- **Docs:** delete `docs/hiring/`, `docs/marketing/`,
  `docs/operations/cto-*`, `docs/upgrade-roadmap.md`,
  `docs/meaningful-milestone-plan.md`, `docs/USER_GUIDE.md`,
  `docs/scrutineering.md` (duplicates the PRD), `docs/scrutineering-guide.md`,
  `docs/TESTING_GUIDE.md`, `docs/testing-guide.md`,
  `docs/database-schema-design.md`, `docs/db-schema-design.md`,
  `docs/schema-design.md`, and every `docs/operations/*` and `docs/security/*`
  page about a removed feature. Move `CONTAINER-SENTINEL-PRD.md` to
  `docs/PRD.md`. Phase 5 writes the replacements.
- **Tests:** delete the tests for removed modules (about 41 of the 98 files in
  `tests/`), and `tests/test_v1_readiness.py`, `test_v1_1_readiness.py`, and
  `test_production_*.py` outright.

**Status: done.** Changes beyond the list above:
- **`scripts/backup-postgres.py`** had been importing the removed
  `src/remediation/backup.py` since 1b, so it was replaced by a tested
  `make backup` target (`pg_dump` to `./backups/`, git-ignored).
  `src/scan/registry_diagnostics.py` was removed with its script.
- **Kept scripts:**
  - repository checks: doc links, deployment config, frontend config, and
    the dashboard build check (`dashboard/package.json` uses it)
  - `smoke-dashboard.mjs` and `smoke-live-scan.mjs` (`make smoke`)
  - `smoke-milestone1.mjs` and `verify-live-scan-edges.mjs` were removed:
    they overlapped `smoke-live-scan.mjs`, and Phase 3's golden-path test
    replaces them.
- **Docs, 66 → 18:**
  - Removed as well as the list above: the production readiness checklist,
    on-call playbook, scanning-engine design, scanner resilience, remediation
    lifecycle, and staging readiness and post-merge drills. These described
    the Node CI and rollout controls, `ScanService`, or deleted scripts.
  - `docs/api/dashboard-v1.md` was rewritten from the current route table,
    including the required roles.
  - The kept operations docs were corrected, and the ADR is marked superseded.
  - Every relative link in the docs resolves.
- **Tests:** the tests for removed modules came out in 1a–1d as each group landed.

**Phase 1 result:**
- tracked files: 593 → 233
- non-test source: 324 files / ~26k lines → 115 files / ~8.6k lines
- Compose services: 8 → 7

**Phase 1 is done when:**
- `docker compose up` starts exactly these services: `api`, `dashboard`,
  `celery-worker`, `celery-beat`, `postgres`, `redis`, `registry`.
- `pytest` passes.
- The dashboard builds.
- You can scan an image from the Images page and see its findings.

Expected size: roughly 324 → 157 non-test source files and about 26k → 10k lines.

---

## Phase 2 — Fix the scan and finding data model (size: M)

The bugs found in the review, each with a regression test.

**Status: done.** 2a (the data model) checked off these items:
- **Observations:** findings stay one row per image, each scan records what it
  saw in `finding_observations`, and the old scan detail pages keep their lists.
  Migration `0002` carries each finding's old `scan_id` over as an
  observation, backfills `vuln_key`, and drops `scan_id` and `remediated`.
- **One scan-creation path:** `src/scan/records.py` creates the image and the
  pending scan for every caller: dashboard, retry, scheduler, discovery and
  post-merge. The worker never creates images. Each scan stores its exact
  `target`, so retries of directory scans work.
- **Identity:** `repo_name` keeps the registry host and Docker Hub names are
  normalized, so the display name is the scannable reference. The
  `other/registry:5000/...` names are gone.
- **Failure states:** every worker exit, a failed save, and a queue that
  rejects the task all end the scan as `failed`. A cancellation is never
  overwritten.
- **Silent rollbacks:** the publish route that rolled back its own failure
  record was removed in 1c. The worker records publication failures through
  `_blocked` in the same session.
- **Also removed:** the unused Image, Scan and Finding repositories (a third
  persistence path), the broken `run_batch_scan` task, and the stale
  `run_image_scan` route.
- **Tests:** they now run against a real schema (an in-memory SQLite fixture
  in `tests/conftest.py`). Before, every worker test ran with no tables and
  status updates failed silently.

**2b done (scanner configuration):**
- **Digest pinning:** each scan resolves its tag to a digest through the
  registry API, answering the auth challenge so public Docker Hub and GHCR
  images resolve anonymously. It then scans `repo@sha256:...` and records the
  digest on the scan and image. Because the scanner cache is keyed on that
  reference, a moved tag can no longer return stale cached results.
  `REQUIRE_IMMUTABLE_SCAN_IDENTITY=true` fails a scan that can't be resolved.
- **Credentials:** they are chosen by registry host: Docker Hub, `GITHUB_TOKEN`
  for ghcr.io, `GITLAB_TOKEN`, or `REGISTRY_CREDENTIALS_JSON` for any other
  host. They reach Trivy as `TRIVY_USERNAME`/`TRIVY_PASSWORD` and Grype as
  `GRYPE_REGISTRY_AUTH_*`. The placeholder `--secret` flag is gone.
- **Plain HTTP:** allowed only for the local registry. Inherited
  `TRIVY_INSECURE`/`GRYPE_REGISTRY_*` values no longer apply to every registry.
- **Settings:** `src/scan/settings.py` reads the scanner settings (timeout,
  output and finding limits, cache directory, retries) and rejects invalid
  values. Both scanners are built from them. `SCHEDULE_CRON_SCAN` drives the
  beat schedule.
- **Retries:** transient scanner failures are retried with exponential
  backoff, up to `SCANNER_RETRY_ATTEMPTS`.
- **Correction to the review:** severities were never limited. The Trivy
  wrapper always passed an explicit `--severity` listing every level, which
  overrides `TRIVY_SEVERITY`, and `GRYPE_SEVERITY_THRESHOLD` isn't a Grype
  setting. Both were no-ops and were removed; D5 (collect everything) already
  held.
- **`src/scan/registry.py`:** reduced to the credential and digest code the
  worker uses. No production code called the rest (login helpers,
  `docker pull`, `docker inspect`).

**Phase 2 is done.**


- [x] **Split findings from observations.**
  - `findings` table: one row per (image, fingerprint), with `first_seen`,
    `last_seen`, `resolved_at`, `reopened_at`, and `status` (open, resolved,
    accepted, or false positive).
  - New `finding_observations` table: (scan_id, finding_id, severity,
    fixed_version, file_path).
  - Stop rewriting `finding.scan_id` on rescan (`src/scan/utils/db.py:155`).
  - The scan-detail page then reads observations, so old scans keep their
    findings.
- [x] **Use one image-identity function.** Today the API creates the image
  record from `parse_image_reference(raw)` while the worker uses
  `storage_reference(raw)`. For `fs:` targets these produce different records.
  Create the image record only in the API and pass `image_id` to the worker.
  The worker must never create an image.
  Also fix the display name: local-registry images render as
  `other/registry:5000/repo:tag`, because the `other` registry label is
  prepended to a name that already includes the host.
- [x] **Fail honestly.**
  - If saving findings fails, mark the scan `failed` instead of `completed`
    (`src/scan/tasks.py:441`).
  - If the worker raises before the first status update (for example, when
    `storage_reference` throws), the scan stays `pending` forever. Wrap the
    task body so every exit writes a terminal status.
- [x] **Show scheduled scans.** Scheduled and discovery scans should create a
  `pending` scan record before they are queued, like manual scans already do.
- [x] **Line severity settings up with the UI.** Default `TRIVY_SEVERITY` and
  `GRYPE_SEVERITY_THRESHOLD` to include MEDIUM and LOW, or drop medium and low
  from the charts. Pick one.
- [x] **Fix the fingerprint semantics.**
  - Keep `fingerprint = cve + package + version` for finding identity.
  - Add an indexed `vuln_key = cve + package` so verification can ask "is
    CVE-X in package-Y still present at any version?"
- [x] **Stop silent rollbacks.** Publication failure records currently roll
  back with the HTTP error (`dashboard_api.py:1290`). Commit the failure in its
  own session before raising.
- [x] **Remove the dead `remediated` flag** from `scan_findings`. Resolution
  comes only from `resolved_at`, set by a later complete scan.
- [x] **Enforce immutable image identity in the worker.**
  - Resolve each tag to a digest before scanning (`src/scan/registry.py`
    already has `resolve_registry_digest`).
  - Store that digest on the scan.
  - When `REQUIRE_IMMUTABLE_SCAN_IDENTITY=true`, fail scans that can't be
    resolved.
  - This only ever existed in the removed `ScanService`.
- [x] **Wire registry credentials into the scanners.** `registry_credentials_from_env`
  is never called on the scan path. Separately, `trivy.py:105` inserts a
  placeholder `--secret` flag whenever credentials are set. Pass credentials
  through `TRIVY_USERNAME`/`TRIVY_PASSWORD` and the `GRYPE_REGISTRY_AUTH_*`
  variables instead.
- [x] **Make scanner settings real or remove them.** `SCANNER_TIMEOUT` (compose
  sets 1800) and `SCANNER_MAX_OUTPUT_BYTES`/`SCANNER_MAX_FINDINGS` are never
  read, so the scanners use their built-in 600 s and 50 MB defaults.
  `SCHEDULE_CRON_SCAN` is also ignored, because the beat schedule hard-codes
  `0 */6 * * *`.
- [x] **Add scanner retries for transient failures** (registry timeouts, DB
  download) in `run_scanners_concurrently`. The old retry and circuit-breaker
  logic was in `ScanService` only.
- [x] **Remove `fs:` targets from the public scan form.** Filesystem scans
  become an internal remediation tool (Phase 4), limited to paths under the
  configured workspace.

**Done when:**
- Rescanning an image three times leaves each scan's detail page showing what
  that scan saw.
- Image totals equal the open findings.
- No test fakes the persistence layer for these paths.

---

## Phase 3 — Golden-path test and readable code (size: M)

- [x] **Build a fixture image.** `fixtures/images/vulnerable-node/` holds a
  tiny `Dockerfile` (`FROM node:18.12-alpine`, plus a `package.json` and lockfile
  pinning a dependency with a known fixed CVE).
- [x] **Write a deterministic golden-path test** (`tests/e2e/test_golden_path.py`)
  that runs in CI. It uses recorded Trivy and Grype JSON for the fixture before
  and after the fix, plus the real API, worker functions, and SQLite. It runs:
  scan → findings → propose → approve → execute (fake builder) → rescan with
  the "after" JSON → finding resolved → remediation `completed`. Mark the
  remediation steps `xfail` until Phase 4 lands them.
- [x] **Add a live variant** (`make e2e`) that runs the same flow against
  `docker compose` with real scanners and the local registry. Run it before
  every merge to `main`; it doesn't run in unit CI.
- [x] **Split `src/analytics/dashboard_api.py`** (1,728 lines) into
  `src/api/routes/{scans,images,findings,remediations,audit,webhooks,session}.py`
  plus `src/api/schemas.py` (the Pydantic models) and `src/api/serializers.py`
  (the `_payload` helpers).
- [x] **Reformat `dashboard/src`** with Prettier, then break the single-line
  page components into components and hooks (`useScan`, `useRemediation`, and
  so on). Start with `remediations/[id]`, `scans/page`, and `dashboard/page`.

**3a status: done.**
- **Fixture:** `fixtures/images/vulnerable-node`, from `node:18.12-alpine`,
  pins `lodash@4.17.20` (CVE-2021-23337, fixed in 4.17.21).
- **Recorded output:** `scripts/record-golden-fixtures.sh` (`make
  record-fixtures`) builds the fixture as "before", plus an "after" image
  (`node:18.20.8-alpine`, lodash 4.17.21). It scans both with the worker's
  real Trivy and Grype and saves trimmed JSON under `fixtures/scanner-output/`.
- **Deterministic test:** `tests/e2e/test_golden_path.py` drives the real app
  over HTTP. Fake `trivy` and `grype` binaries on PATH replay the recorded
  output. The scan half and the patched-image rescan pass. The remediation half
  is `xfail(strict=True)` and fails at `actionable_count == 0`, the Phase 4 gap.
- **Live test:** `make e2e` builds and pushes the fixture, scans it with real
  scanners through the dashboard, and checks the lodash finding.
- **Bug found by the first live run:** Grype has no title field, so long
  descriptions became titles over the 1024-character column, and Postgres
  rejected the insert. Thanks to Phase 2a's honest failure states the scan
  failed visibly instead of showing completed. Text is now fitted to its
  columns, and a golden-path test checks every saved value against its column
  length, because SQLite doesn't enforce them.
- **Finding for Phase 4:** bumping the base image to `node:18.20.8-alpine`
  fixes 80 findings but introduces 93, 20 of them critical or high. Both were
  scanned the same day with the same database: newer OpenSSL, musl and zlib
  releases carry CVEs the old ones didn't. A strict "no new critical/high"
  rule would reject every such bump; see decision D6.

**3b status: done.**
- **The split:** `dashboard_api.py` (1,098 lines after the Phase 1 cuts)
  became `src/api/schemas.py`, `src/api/serializers.py` and
  `src/api/routes/{posture,scans,images,findings,session,audit,remediations,webhooks}.py`,
  plus `_access.py` for role checks and operator audit events. The largest
  module is 260 lines.
- **Names:** shared helpers are now public (`scan_payload`, `paginate`,
  `require_role`, and the rest). `src/analytics/` is gone.
- **Routes unchanged:** the OpenAPI table (35 method-and-path pairs and their
  operation IDs) is identical to `main` before the split.

**3c status: done. Phase 3 is complete.**
- **Formatting:** Ruff and Prettier formatted the whole codebase in one
  mechanical commit.
- **Line length and lint:** the remaining over-long lines (mostly Tailwind
  class strings, which Prettier can't split) go through a small `cx()`
  helper. `make fmt-check` (Ruff format and lint, Prettier, and
  `scripts/check-line-length.mjs`) now blocks in CI, and the image-build job
  depends on it. No source line is over 120 characters; generated
  migrations are excluded.
- **Pages broken up:** the three pages the plan named are now hooks and
  components:
  - **Scans:** 447 lines down to about 190, using `useScanHistory`,
    `useScanWatcher` and `components/scans/*`.
  - **Overview:** 479 down to about 170, using `useDashboardData` and
    `components/dashboard/*`.
  - **Remediation detail:** 280 down to about 80, using `useRemediation` and
    `components/remediations/*`.
  - **Shared code:** `lib/http.ts` (fetch helpers with readable API errors),
    `lib/status.ts`, `usePermissions` and `Pagination`.
- **Bugs fixed while splitting:**
  - The scan watcher never stopped for `partial` scans.
  - The scan filter had no `partial` option.
  - Recent scans linked to the list, not the scan.
  - The overview's "Continuous protection enabled" and "Monitoring active"
    were hard-coded regardless of state.
  - The overview's copy still described the deployment observation and alert
    delivery removed in 1c.
  - A remediation that failed to load showed an endless spinner.
  - Execution status was re-polled on a fixed 3, 8 and 15 s schedule instead
    of until the worker reports.

**Done when:** the golden-path test exists and its scan half passes, no source
line is over 120 characters, and no route file is over about 400 lines.

---

## Phase 4 — Rebuild remediation around images (size: L)

Today remediation is a find-and-replace in one globally configured repository,
and container-image findings are never eligible. This phase makes "fix this
image" a real operation.

### 4a. Link images to their source
- [x] New `image_sources` table: `image_id` (or a repo-name pattern),
  `repo_url` or local path, `default_branch`, `dockerfile_path`,
  `build_context`, `build_args` (JSON), `ecosystems` (detected), and optional
  provider settings.
- [x] Add a dashboard form on the image detail page: "Connect source". An image
  without a source shows findings but explains what fixing it requires.
- [ ] Remove the global `REMEDIATION_REPOSITORY_ROOT`, `REMEDIATION_EVIDENCE_FILE`,
  `REMEDIATION_EVIDENCE_ARTIFACT_FILE`, `REMEDIATION_VALIDATION_PROVIDER`, and
  `REMEDIATION_VALIDATION_ECOSYSTEM` env vars.

### 4b. Decide which fix applies to each finding
Done. `src/remediation/planner.py` classifies each finding from the scanner's
package type (scan records do not keep layer history, so the API decides from
finding data alone and the worker resolves files and lines against the checkout):

| Strategy | When | Change |
|---|---|---|
| `dependency_update` | npm or pip package with a fixed version | Run the package manager (`npm install pkg@ver --package-lock-only`, pip pin) instead of editing text. |
| `os_package_upgrade` | apk/deb/rpm package with a fixed version, whichever layer added it | Upgrade those packages in the final build stage. Narrower than a base-image bump, so it rarely brings new findings. |
| `base_image_bump` | Runtime binary shipped by the base image (Grype `binary`, e.g. `node`) | Rewrite `FROM` to the newest tag in the same line, found through the registry tags API. |
| `manual` | No fixed version, or an ecosystem without an updater | Shown with the reason; never proposed. |

- [x] The preview returns one action per fix (Trivy and Grype findings for the
  same package merge), the findings and `vuln_key`s each is expected to close,
  and the findings left for manual work. Proposing requires a connected source.

### 4c. Apply, build, verify
Done (D3: rootless `buildkitd`; D6: `needs_acceptance`). See
[remediation execution](operations/remediation-execution.md).

- [x] Clone the source at its ref into a temporary directory and apply the
  actions (npm via the package manager, pip pins, OS upgrade line, `FROM` bump).
- [x] Build with the rootless `buildkitd` service and push
  `<repository>:scrutineering-candidate-<id>` to the local registry.
- [x] Scan the candidate by digest with the same scanners; `failed` if a
  targeted `vuln_key` remains, `needs_acceptance` if new critical/high appear,
  otherwise `ready`. The patch, candidate and verdict are stored on the remediation.
  The `trivy fs --exit-code 1` gate, signed-evidence gate and
  `remediation-evidence.yml` are removed.
- [x] `make e2e` runs the whole loop live and the golden-path test has no `xfail`.
- [ ] Run the source's `test_command`. Not done: running repository code inside
  the worker is not isolated enough. It belongs in a BuildKit stage, as a follow-up.

### 4d. Publish and close
Done. `published` sits between `ready` and `completed` (migration 0007).
- [x] Without a provider configured, the remediation ends at `ready`. The
  operator gets the diff (`patch`, against `source_commit`) and the candidate image.
- [x] With GitHub configured, push the branch and open a PR
  (`src/remediation/publish.py`). The PR body holds the plan and the before/after
  scan comparison.
- [x] When the merge webhook arrives, rescan; scheduled scans also count. The
  webhook trusts only the pull request's state, no digests or counts.
  `completed` when the targeted findings are gone from the image. `failed` with a
  reason if the PR is closed unmerged, or if a rebuilt image (new digest) still has
  them.

Conservative choices:
- Publishing is an explicit security-operator action (`POST /publish`), never
  automatic. `GITHUB_TOKEN` also authenticates ghcr.io scans, so setting it must
  not open pull requests.
- No separate repository allowlist: the target is the image's connected source,
  and the token's repository selection bounds what can be reached.
- The branch is `scrutineering/remediation-<id>`. The commit timestamp is fixed,
  so a retry pushes the same commit. Pushes use a lease, so another author's
  branch is never overwritten.
- A merged PR whose image has not been rebuilt (same digest) stays `published`.
  It is not failed, because merging alone does not change the image.
- github.com sources are cloned with `GITHUB_TOKEN` for execution as well, so
  private repositories work. No other source ever receives the token.
- The old publisher, branch-protection check, rollback plan and post-merge
  evidence modules were removed, along with their columns.

### 4e. One state machine
Done. `remediations.status` is the only current state (migration 0005 maps the
old values): `proposed → approved → building → verifying → ready → completed`,
with `needs_acceptance` between `verifying` and `ready` (D6), plus `failed` and
`cancelled`. Transitions live in `src/remediation/state_machine.py`.
`workflow_state`/`workflow_label` are gone; events are history only.

- A failed remediation retries from `proposed`, so it is approved again, rather
  than from `approved`.
- The server sets `completed` when a complete rescan of the image no longer
  shows any targeted `vuln_key`.

**Done when:** the golden-path test passes with no `xfail`s, and `make e2e`
fixes the fixture image's base-image CVE and one npm CVE, both verified by rescan.

---

## Phase 5 — Docs and dashboard flow (size: S–M)

- [ ] `README.md`: what it is, a 5-minute quick start (`cp .env.example .env &&
  make up && make migrate`), push a test image, and a link to the operator guide.
  Under 150 lines.
- [ ] `docs/ARCHITECTURE.md`: one diagram of the services and the loop, the data
  model, and the state machines.
- [ ] `docs/OPERATOR_GUIDE.md`: scan an image, triage findings, connect a source,
  run a remediation, and read the results.
- [ ] `docs/CONFIGURATION.md`: generated from one settings module
  (`src/config.py`, pydantic-settings) that becomes the only place env vars are read.
- [ ] Trim the dashboard navigation to Overview · Images · Scans · Remediations ·
  Audit. Each page links forward to the next step in the loop.
- [ ] Add a CI check that every Markdown link resolves.

---

## Phase 6 — Bring back, one at a time (later)

Each of these needs its own short design note, and has to keep the golden-path
test green: OIDC and forward-auth, Kubernetes manifests, GitLab publishing,
notifications (Slack or webhook), scheduled reports and compliance export,
runtime discovery on by default, signed SBOM and evidence, deployment
observation, multi-user roles.

---

## Decisions needed

| ID | Question | Recommendation |
|---|---|---|
| D1 | Keep `k8s/` in the repo during the reset? | Remove it; it's in the tag. Target Docker Compose on the home lab until Phase 6. |
| D2 | Drop-table migration, or squash migrations? | **Decided: squash** (Phase 1d). |
| D3 | How should the worker build images? | **Decided: a rootless `buildkitd` service** (Phase 4c). |
| D4 | First PR provider? | **Decided: GitHub only.** The GitLab merge-request publisher, callback parsing and webhook route are removed (Phase 4c); Phase 4d builds publication on GitHub alone. |
| D5 | Which severities do the scanners collect by default? | **Decided: all** (already true; see Phase 2b). |
| D6 | How should verification treat a base-image bump that fixes some findings but introduces new critical/high ones? | **Decided: require acceptance.** The candidate goes to `needs_acceptance`, listing the new critical/high findings; a security operator accepts (→ `ready`) or cancels (Phases 4c, 4e). |

## Mapping review findings to phases

| Review finding | Fixed in |
|---|---|
| Image findings can never be remediated | 4a–4c |
| One global repo, evidence file, and ecosystem | 4a |
| Text-replace edits break lockfiles | 4b |
| `--exit-code 1` rescan always fails partial fixes | 4c |
| Remediations never reach `completed`; three state systems | 4e |
| Approval token round trip; client-asserted verification | 1c, 4d |
| Rescans erase scan history (`scan_id` rewrite) | 2 |
| `fs:` scans split across two image records | 2 |
| Scan marked completed after persistence failure | 2 |
| Publication failure record rolled back | 2 |
| Severity defaults versus charts | 2 |
| `.env.example` missing remediation roles | 0 |
| Unused Node planner and duplicate publishers | 1a |
| Fake readiness drills and unused subsystems | 1b, 1e |
| Tests that never exercise the loop | 3 |
| Single-line components, 1,728-line route file | 3 |
| Contradictory, sprawling docs | 1e, 5 |
