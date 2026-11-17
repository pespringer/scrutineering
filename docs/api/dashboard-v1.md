# Dashboard API v1

The dashboard API is mounted at `/api/dashboard` on the Python API
(`src/api/routes/`, one module per section below). Every route except the provider webhook
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
| POST | `/remediations/preview` | remediator | How the selected findings would be fixed; changes nothing |
| POST | `/remediations` | remediator | Propose a remediation (status `proposed`); the image needs a connected source |
| GET | `/remediations?status&limit&offset` | remediator | Paginated remediation queue |
| GET | `/remediations/{id}` | remediator | Remediation detail with actions and publications |
| GET | `/remediations/{id}/events` | remediator | Ordered history of the remediation |
| POST | `/remediations/{id}/approve` | security-operator | `proposed` → `approved` |
| POST | `/remediations/{id}/execute` | remediator | `approved` → `building`; requires `REMEDIATION_EXECUTION_ENABLED=true` |
| POST | `/remediations/{id}/accept` | security-operator | `needs_acceptance` → `ready`: accept new critical/high findings |
| POST | `/remediations/{id}/publish` | security-operator | Queue a GitHub pull request for a `ready` remediation (→ `published`); 503 without `GITHUB_TOKEN`, 422 if the source is not on github.com |
| POST | `/remediations/{id}/retry` | security-operator | `failed` → `proposed` (approval is required again) |
| POST | `/remediations/{id}/cancel` | remediator | Any open status → `cancelled`; releases the findings |
| GET/PUT/DELETE | `/images/{id}/source` | remediator to change | The repository, ref, Dockerfile and build context the image is built from |

Statuses, in order: `proposed`, `approved`, `building`, `verifying`, then
`ready` (or `needs_acceptance` when the patched image adds new critical or high
findings), then `completed`. `failed` and `cancelled` end a run. The server sets
`completed` itself, when a complete rescan of the image no longer shows any
targeted finding. The `status` column is the only current state; events are
history.

`operator` and `remediator` routes also accept `security-operator`.

A remediation can be proposed for open findings on an image with a connected
source, when each finding has an automatic fix (see the preview's `manual` list
for the ones that do not). Execution patches the source, builds a candidate
image with BuildKit, and scans it; see
[remediation execution](../operations/remediation-execution.md). The detail
payload includes the `patch`, `candidate_image`, `candidate_digest` and
`verification` it produced.

## Provider webhooks

`POST /webhooks/github` authenticates with GitHub's HMAC signature
(`GITHUB_WEBHOOK_SECRET`), not the API key. GitHub is the only provider (decision D4).
Delivery IDs are recorded, so replays are accepted without reprocessing. Only
`pull_request` `closed` events for a published remediation's pull request change
anything: a merge marks the publication merged and queues a rescan of the image; a
close without merging fails the remediation. Nothing else in the payload is
trusted; the server's own scans decide whether the fix landed.
