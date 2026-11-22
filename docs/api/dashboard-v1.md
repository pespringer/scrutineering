# Dashboard API v1

The dashboard API is mounted at `/api/dashboard` on the Python API
(`src/api/routes/`, one module per section below). Every route except the provider webhook
requires `PYTHON_API_KEY`, service authentication, or a verified trusted-proxy
identity. The Next.js dashboard calls these routes server-side, so API keys and
the proxy secret never reach the browser.

**Roles.** Local API-key sessions get the roles in `DASHBOARD_DEFAULT_ROLES`. A
trusted ingress may forward `x-authenticated-sub`, `x-authenticated-email` and
`x-authenticated-roles`, which are accepted only alongside the matching
`x-dashboard-proxy-secret` (`DASHBOARD_TRUSTED_PROXY_SECRET`). Each route that
needs a role checks one action from `src/api/roles.py`; the Role column below names
the least role that holds it, and `admin` holds every action. A missing action is
`403 operator_role_required`.

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
| GET | `/system-status` | any | `operational`, `degraded` or `unavailable`, from the database, the scan queue, responding workers and runtime discovery, with the `problems` found and the last scan |

## Scans

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/scans?limit&offset&status&search&include_archived` | any | Paginated scan history |
| GET | `/scans/health` | any | Status counts and terminal rate over recent scans |
| GET | `/scans/{scan_id}` | any | One scan's status, for polling, with `sbom` (its SBOM's summary, or null) |
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
| GET | `/images/{image_id}?severity&limit&offset` | any | Image detail and its open findings, with `sbom` (the latest SBOM's summary) |
| GET | `/images/{image_id}/sbom` | any | The latest SBOM (CycloneDX JSON); `X-Scrutineering-SBOM-SHA256` and `-Scan-ID` headers |
| GET | `/scans/{scan_id}/sbom` | any | That scan's SBOM, with `X-Scrutineering-Signature` and `-Key-ID` when signed; 404 when it has none |
| GET | `/scans/{scan_id}/sbom.sig` | any | The SBOM's base64 signature (cosign blob format); 404 when unsigned |
| GET | `/images/{image_id}/deployments` | any | Running containers (and those gone within 24 h), each `current`, `stale` or `unknown` against the latest scan |
| GET | `/reports?limit` | any | Weekly and on-demand reports, newest first |
| GET | `/reports/{id}` | any | One report: summary and the parsed `scrutineering.report/v1` document |
| GET | `/reports/{id}.json` | any | The report's bytes exactly as signed, with `X-Scrutineering-Signature` |
| GET | `/reports/{id}.sig` | any | The report's base64 signature; 404 when unsigned |
| POST | `/reports` | admin | Queue an on-demand report for this week so far (202) |
| POST | `/compliance/exports` | security-operator | `{ "since": "2026-07-01", "until": "2026-09-30" }` (UTC days, both included, at most 366); 202, or 409 while one is building |
| GET | `/compliance/exports` | security-operator | The last 20 exports: status, files, size, SHA-256, error |
| GET | `/compliance/exports/{id}/download` | security-operator | The zip, with `X-Scrutineering-Export-SHA256`; 404 until ready or after 24 h |
| GET | `/signing-keys` | any | Every public key that signed exports: `key_id`, PEM, created |
| GET | `/signing-keys/{fingerprint}.pem` | any | One public key as PEM; `fingerprint` is the hex part of its `key_id` |
| GET | `/registry/inventory` | dashboard, operator | Local registry tags joined with scan state |
| POST | `/images/bulk-archive` | operator | Mark images inactive |
| POST | `/findings/bulk-acknowledge` | operator | Acknowledge open findings |
| POST | `/findings/bulk-assign` | operator | Assign open findings: `{ "finding_ids": [...], "assignee": "alice" }` (`null` unassigns). In `trusted-proxy` mode the assignee must be a recorded person's subject, else `422 unknown_assignee` |
| GET | `/findings/export` | dashboard, operator | Bounded JSON export of findings with a SHA-256 |

## Session and audit

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/session` | any | The caller's identity and roles |
| GET | `/permissions` | any | `roles`, `subject`, `actions` (the caller's allowed actions), the `can_*` flags derived from them, and `separate_approver` |
| GET | `/audit?limit&offset&actor&event_type&since&until` | any | Paginated audit trail |
| GET | `/people` | admin | Everyone recorded at sign-in: `subject`, `email`, `roles` (at last sign-in), `first_seen_at`, `last_seen_at` |
| GET | `/people/assignees` | operator | Who findings can be assigned to: `subject` and `email` only |
| GET | `/audit/export` | security-operator | Bounded audit export with a SHA-256 |

## Notifications

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/notifications` | security-operator | Whether Slack and the webhook are configured (never their URLs), `NOTIFICATION_EVENTS`, whether messages carry links, and the last 20 deliveries |
| POST | `/notifications/test` | security-operator | Queue a sample message (event `test`) to each configured channel through the normal outbox; 202 with the queued deliveries, 409 when no channel is configured |

## Remediation

| Method | Path | Role | Purpose |
|---|---|---|---|
| POST | `/remediations/preview` | remediator | How the selected findings would be fixed; changes nothing |
| POST | `/remediations` | remediator | Propose a remediation (status `proposed`); the image needs a connected source |
| GET | `/remediations?status&limit&offset` | remediator | Paginated remediation queue |
| GET | `/remediations/{id}` | remediator | Remediation detail with actions, publications, who took each step (`proposed_by`, `approved_by`, `executed_by`, `accepted_by`, `published_by`), `evidence` (the bundle's summary) and, once completed, `deployment` (`{containers, fixed, not_fixed}`) |
| GET | `/remediations/{id}/events` | remediator | Ordered history of the remediation |
| GET | `/remediations/{id}/evidence` | remediator | The latest signed evidence bundle (canonical JSON), with `X-Scrutineering-Signature`; 404 until it ends |
| GET | `/remediations/{id}/evidence.sig` | remediator | The bundle's base64 signature; 404 when unsigned |
| POST | `/remediations/{id}/approve` | security-operator | `proposed` → `approved`; `403 separate_approver_required` when the caller proposed it and separation of duties is on |
| POST | `/remediations/{id}/execute` | remediator | `approved` → `building`; requires `REMEDIATION_EXECUTION_ENABLED=true` |
| POST | `/remediations/{id}/accept` | security-operator | `needs_acceptance` → `ready`: accept new critical/high findings; refused to the proposer like approve |
| POST | `/remediations/{id}/publish` | security-operator | Queue a GitHub pull request for a `ready` remediation (→ `published`); 503 without `GITHUB_TOKEN`, 422 if the source is not on github.com |
| POST | `/remediations/{id}/retry` | security-operator | `failed` → `proposed` (approval is required again); the caller becomes the proposer |
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
