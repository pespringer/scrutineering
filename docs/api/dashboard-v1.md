# Dashboard API v1

The dashboard API is mounted at `/api/dashboard` on the Python API
(`src/analytics/dashboard_api.py`). Every route except the provider webhook
requires `PYTHON_API_KEY`, service authentication, or a verified trusted-proxy
identity. The Next.js dashboard calls these routes server-side, so API keys and
the proxy secret never reach the browser.

**Roles.** Local API-key sessions get the roles in `DASHBOARD_DEFAULT_ROLES`. A
trusted ingress may forward `x-authenticated-sub`, `x-authenticated-email` and
`x-authenticated-roles`, which are accepted only alongside the matching
`x-dashboard-proxy-secret` (`DASHBOARD_TRUSTED_PROXY_SECRET`). `admin` satisfies
every role check.

**Pagination.** Paginated responses use `{ items, limit, offset, count, total }`.

**Images, scans and findings.** An image is one `repo_name:tag`; `name` is its
display reference (for example `registry:5000/team/app:1.0`). Every scan is
created as `pending` before it is queued, and ends `completed`, `partial`,
`failed` or `cancelled`. A finding is one vulnerability on one image across
scans: a complete scan that no longer sees it sets `resolved_at`, and seeing it
again reopens it. Each scan's own view of its findings is kept, so older scans
show what they found at the time.

## Posture

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/posture/summary` | any | Open-finding counts by severity and the latest scan state |
| GET | `/posture/trend?days=30` | any | Daily severity snapshots for the window |

## Scans

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/scans?limit&offset&status&search&include_archived` | any | Paginated scan history |
| GET | `/scans/health` | any | Status counts and terminal rate over recent scans |
| GET | `/scans/{scan_id}` | any | One scan's status, for polling |
| GET | `/scans/{scan_id}/findings?severity&fixable_only` | any | The findings this scan observed, as it saw them, with their current lifecycle state |
| POST | `/scans` | operator | Queue a scan: `{ "image_name": "nginx:1.27", "priority": "normal" }`. Container image references only; `fs:` targets return 422 |
| POST | `/scans/{scan_id}/cancel` | operator | Cancel a pending or running scan |
| POST | `/scans/bulk-cancel` | operator | Cancel several scans: `{ "ids": [...] }` |
| POST | `/scans/bulk-retry` | operator | Re-queue failed or cancelled scans with their original target |
| POST | `/scans/bulk-archive` | operator | Hide finished scans from history |

## Images and findings

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/images?limit&offset&search&severity` | any | Image inventory with open and resolved counts |
| GET | `/images/{image_id}?severity&limit&offset` | any | Image detail and its open findings |
| GET | `/registry/inventory` | dashboard, operator | Local registry tags joined with scan state |
| POST | `/images/bulk-archive` | operator | Mark images inactive |
| POST | `/findings/bulk-acknowledge` | operator | Acknowledge open findings |
| POST | `/findings/bulk-assign` | operator | Assign open findings: `{ "finding_ids": [...], "assignee": "alice" }` |
| GET | `/findings/export` | dashboard, operator | Bounded JSON export of findings with a SHA-256 |

## Session and audit

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/session` | any | The caller's identity and roles |
| GET | `/permissions` | any | Dashboard capabilities derived from roles |
| GET | `/audit?limit&offset&actor&event_type&since&until` | any | Paginated audit trail |
| GET | `/audit/export` | security-operator | Bounded audit export with a SHA-256 |

## Remediation

| Method | Path | Role | Purpose |
|---|---|---|---|
| POST | `/remediations/preview` | remediator | Proposed actions for selected findings; changes nothing |
| POST | `/remediations` | remediator | Create a remediation in `requires_review` |
| GET | `/remediations?status&limit&offset` | remediator | Paginated remediation queue |
| GET | `/remediations/{id}` | remediator | Remediation detail with actions and publications |
| GET | `/remediations/{id}/events` | remediator | Ordered execution events |
| POST | `/remediations/{id}/approve` | security-operator | Approve (no body); moves the record to `analyzing` |
| POST | `/remediations/{id}/execute` | remediator | Queue execution; requires `REMEDIATION_EXECUTION_ENABLED=true` |
| POST | `/remediations/{id}/retry` | security-operator | Return a failed remediation to review |

`operator` and `remediator` routes also accept `security-operator`.

A remediation can be created only for open findings that have a fixed version
and a source file path. Today that means findings from `fs:` (directory)
scans; Phase 4 of the reset plan extends remediation to container images.

Execution runs on the worker. It requires a signed evidence envelope and a
validation provider/ecosystem, applies the edits in an isolated worktree, and
runs install, test, build, SBOM and rescan steps. When `REMEDIATION_PUSH_ENABLED`
and `REMEDIATION_PUBLICATION_ENABLED` are set and the repository is in
`REMEDIATION_ALLOWED_REPOSITORIES`, the worker pushes a branch and opens a PR.
It never merges. Blocked runs are recorded as events with a reason.

## Provider webhooks

`POST /webhooks/{github|gitlab}` authenticates with the provider's HMAC
signature (`GITHUB_WEBHOOK_SECRET` / `GITLAB_WEBHOOK_SECRET`), not the API key.
Delivery IDs are recorded, so replays are accepted without reprocessing. A merge
callback updates the matching publication. If the callback carries digest and
scan evidence it is evaluated immediately; otherwise a follow-up scan is queued
and the publication stays `pending` until it completes.
