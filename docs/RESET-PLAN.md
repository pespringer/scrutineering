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

### 1d. Database

Tables with no remaining code after 1a–1c: `raw_scan_results`,
`security_policies`, `policy_evaluations`, `compliance_reports`,
`audit_chain_anchors`, `forensic_snapshots`, `forensic_network_flows`,
`container_runtimes`, `remediation_release_evidence`,
`remediation_recovery_requests`, `remediation_alert_evidence`,
`remediation_alert_deliveries`, `remediation_reconciliation_runs`.

**Decision needed (D2):** either add one `drop_unused_tables` migration, or
squash all 28 migrations into a fresh baseline. Squashing is cleaner, but you
have to recreate the database (`docker compose down -v` deletes local scan
history). Recommendation: squash. There is no production data, and Phase 2
changes the finding tables anyway.

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

- [ ] **Split findings from observations.**
  - `findings` table: one row per (image, fingerprint), with `first_seen`,
    `last_seen`, `resolved_at`, `reopened_at`, and `status` (open, resolved,
    accepted, or false positive).
  - New `finding_observations` table: (scan_id, finding_id, severity,
    fixed_version, file_path).
  - Stop rewriting `finding.scan_id` on rescan (`src/scan/utils/db.py:155`).
  - The scan-detail page then reads observations, so old scans keep their
    findings.
- [ ] **Use one image-identity function.** Today the API creates the image
  record from `parse_image_reference(raw)` while the worker uses
  `storage_reference(raw)`. For `fs:` targets these produce different records.
  Create the image record only in the API and pass `image_id` to the worker.
  The worker must never create an image.
- [ ] **Fail honestly.**
  - If saving findings fails, mark the scan `failed` instead of `completed`
    (`src/scan/tasks.py:441`).
  - If the worker raises before the first status update (for example, when
    `storage_reference` throws), the scan stays `pending` forever. Wrap the
    task body so every exit writes a terminal status.
- [ ] **Show scheduled scans.** Scheduled and discovery scans should create a
  `pending` scan record before they are queued, like manual scans already do.
- [ ] **Line severity settings up with the UI.** Default `TRIVY_SEVERITY` and
  `GRYPE_SEVERITY_THRESHOLD` to include MEDIUM and LOW, or drop medium and low
  from the charts. Pick one.
- [ ] **Fix the fingerprint semantics.**
  - Keep `fingerprint = cve + package + version` for finding identity.
  - Add an indexed `vuln_key = cve + package` so verification can ask "is
    CVE-X in package-Y still present at any version?"
- [ ] **Stop silent rollbacks.** Publication failure records currently roll
  back with the HTTP error (`dashboard_api.py:1290`). Commit the failure in its
  own session before raising.
- [ ] **Remove the dead `remediated` flag** from `scan_findings`. Resolution
  comes only from `resolved_at`, set by a later complete scan.
- [ ] **Remove `fs:` targets from the public scan form.** Filesystem scans
  become an internal remediation tool (Phase 4), limited to paths under the
  configured workspace.

**Done when:**
- Rescanning an image three times leaves each scan's detail page showing what
  that scan saw.
- Image totals equal the open findings.
- No test fakes the persistence layer for these paths.

---

## Phase 3 — Golden-path test and readable code (size: M)

- [ ] **Build a fixture image.** `fixtures/images/vulnerable-node/` holds a
  tiny `Dockerfile` (`FROM node:18.12-alpine`, plus a `package.json` and lockfile
  pinning a dependency with a known fixed CVE).
- [ ] **Write a deterministic golden-path test** (`tests/e2e/test_golden_path.py`)
  that runs in CI. It uses recorded Trivy and Grype JSON for the fixture before
  and after the fix, plus the real API, worker functions, and SQLite. It runs:
  scan → findings → propose → approve → execute (fake builder) → rescan with
  the "after" JSON → finding resolved → remediation `completed`. Mark the
  remediation steps `xfail` until Phase 4 lands them.
- [ ] **Add a live variant** (`make e2e`) that runs the same flow against
  `docker compose` with real scanners and the local registry. Run it before
  every merge to `main`; it doesn't run in unit CI.
- [ ] **Split `src/analytics/dashboard_api.py`** (1,728 lines) into
  `src/api/routes/{scans,images,findings,remediations,audit,webhooks,session}.py`
  plus `src/api/schemas.py` (the Pydantic models) and `src/api/serializers.py`
  (the `_payload` helpers).
- [ ] **Reformat `dashboard/src`** with Prettier, then break the single-line
  page components into components and hooks (`useScan`, `useRemediation`, and
  so on). Start with `remediations/[id]`, `scans/page`, and `dashboard/page`.

**Done when:** the golden-path test exists and its scan half passes, no source
line is over 120 characters, and no route file is over about 400 lines.

---

## Phase 4 — Rebuild remediation around images (size: L)

Today remediation is a find-and-replace in one globally configured repository,
and container-image findings are never eligible. This phase makes "fix this
image" a real operation.

### 4a. Link images to their source
- [ ] New `image_sources` table: `image_id` (or a repo-name pattern),
  `repo_url` or local path, `default_branch`, `dockerfile_path`,
  `build_context`, `build_args` (JSON), `ecosystems` (detected), and optional
  provider settings.
- [ ] Add a dashboard form on the image detail page: "Connect source". An image
  without a source shows findings but explains what fixing it requires.
- [ ] Remove the global `REMEDIATION_REPOSITORY_ROOT`, `REMEDIATION_EVIDENCE_FILE`,
  `REMEDIATION_EVIDENCE_ARTIFACT_FILE`, `REMEDIATION_VALIDATION_PROVIDER`, and
  `REMEDIATION_VALIDATION_ECOSYSTEM` env vars.

### 4b. Decide which fix applies to each finding
Classify using Trivy's `Result.Class` and `Type`, the image's layer history,
and the Dockerfile:

| Strategy | When | Change |
|---|---|---|
| `base_image_bump` | OS package (`Class=os-pkgs`) introduced in a base layer | Rewrite `FROM` to the newest tag in the same line (for example `node:18.12-alpine` → `node:18.20-alpine`), found by querying the registry. |
| `os_package_upgrade` | OS package installed by a `RUN apk/apt` line in this Dockerfile | Pin or upgrade the package in that `RUN` line. |
| `dependency_update` | Language package (`Class=lang-pkgs`) whose lockfile is in the source repo | Run the package manager (`npm install pkg@ver`, `pip-compile --upgrade-package`, `go get`) instead of editing text. |
| `manual` | No fixed version, or no strategy matches | Show the guidance only. The finding stays eligible for "accept risk". |

- [ ] The preview endpoint returns one plan per remediation: its strategy, the
  exact file and line, and which findings it is expected to close.

### 4c. Apply, build, verify
- [ ] Apply the change in an isolated worktree (`worktree.py` already exists).
- [ ] Build with BuildKit. **Decision needed (D3):** mount the Docker socket
  into the worker (simple, effectively root on the host) or run a rootless
  `buildkitd` sidecar (recommended). Push the result to the local registry as
  `<repo>:scrutineering-candidate-<remediation_id>`.
- [ ] Scan the candidate image with the same scanners and settings as the original.
- [ ] Pass when every targeted `vuln_key` is gone **and** no new CRITICAL or
  HIGH `vuln_key` appeared. Store the diff on the remediation. This replaces the
  `trivy fs . --exit-code 1` gate, which fails whenever any vulnerability remains.
- [ ] Run the repo's tests if the source declares a test command. Make it
  optional for each source, not a global setting.

### 4d. Publish and close
- [ ] Without a provider configured, the remediation ends at `ready`. The
  operator gets the branch, the diff, and the candidate image.
- [ ] With GitHub configured (GitLab later), push the branch and open a PR. The
  PR body holds the plan and the before/after scan diff.
- [ ] When the merge webhook arrives (or on the next scheduled scan of the real
  tag), rescan. Set `completed` when the targeted findings resolve on the real
  image, and `failed` with a reason if they don't.

### 4e. One state machine
Statuses go on `remediations.status` only: `proposed → approved → building →
verifying → ready → published → completed`, plus `failed` and `cancelled`. A
failed remediation can retry from `approved`. `remediation_events` records
transitions and logs but is never read to work out state. Remove
`workflow_state` and `workflow_label` and the logic that derives them from events.

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
| D2 | Drop-table migration, or squash migrations? | Squash, and recreate the local database. |
| D3 | How should the worker build images? | A rootless `buildkitd` sidecar. |
| D4 | First PR provider? | GitHub only. |
| D5 | Which severities do the scanners collect by default? | All of them. Filter in the UI. |

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
