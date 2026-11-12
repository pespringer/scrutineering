# Dashboard API v1

The dashboard data boundary is mounted at `/api/dashboard` on the Python API.
All routes require `PYTHON_API_KEY`, service authentication, or a verified
trusted OIDC ingress identity.

## Read APIs

- `GET /posture/summary` — current open-finding counts and latest scan state.
- `GET /posture/trend?days=30` — severity snapshots for the selected window.
- `GET /scans?limit=20&offset=0&status=running&search=api` — paginated scan
  history.
- `GET /scans/{scan_id}` — durable scan status for polling.
- `GET /images?limit=20&offset=0&search=nginx&severity=high` — paginated image
  inventory.
- `GET /images/{image_id}?limit=25&offset=0&severity=critical` — image detail
  and paginated findings.
- `GET /session` — the mapped operator identity context.
- `GET /permissions` — role-derived dashboard capabilities.
- `GET /audit?limit=25&offset=0` — paginated operator activity records.
- `GET /remediations/{remediation_id}` — remediation preview/status.
- `GET /remediations/{remediation_id}/events` — ordered durable execution
  events and fail-closed reasons.
- `GET /remediations?status=requires_review` — paginated remediation queue.

Paginated responses use `{ items, limit, offset, count, total }`. The Next.js
dashboard proxy keeps API keys and the trusted proxy secret server-side.

## Scan controls

- `POST /scans` with `{ "image_name": "nginx:1.27", "priority": "normal" }`
  persists a pending scan and queues Celery work.
- `POST /scans/{scan_id}/cancel` revokes queued work and records `cancelled`.

Starting and cancelling scans require `operator` or `security-operator`; the
`admin` role is also accepted. Read-only dashboard access remains available to
the `dashboard` role.

## Remediation boundary

- `POST /remediations/preview` returns deterministic, read-only actions for
  selected open findings.
- `POST /remediations` persists a `requires_review` record for findings with
  known fixes; it requires `remediator` or `security-operator`.
- `POST /remediations/{id}/approval-token` issues a short-lived token to a
  `security-operator`; `REMEDIATION_APPROVAL_SECRET` must be configured.
- `POST /remediations/{id}/approve` verifies the token, stores approval
  provenance, and transitions the record to `analyzing`.
- `POST /remediations/{id}/execute` queues an approved record only when
  `REMEDIATION_EXECUTION_ENABLED=true`; otherwise it fails closed.

Execution blocks are persisted as remediation lifecycle events so operators
can distinguish a policy denial, missing adapter configuration, and an actual
worker failure.

When enabled, the worker additionally requires evidence envelope/artifact paths
and a supported provider/ecosystem pair. It applies only exact-match edits in a
detached worktree and runs install, test, build, SBOM, and rescan gates in order.

`POST /remediations/{id}/publication-plan` creates a validated handoff envelope
for the existing GitHub/GitLab publishers. It requires an allowlisted
repository, protected `main`/`master` base, verified evidence, and an
idempotency key; it does not call the provider. `POST
/remediations/post-merge/verify` returns `rollback_required` plus a safe
`git revert --no-edit` plan when digest, scan, or finding checks regress.

`POST /remediations/{id}/publish` is disabled unless
`REMEDIATION_PUBLICATION_ENABLED=true`, requires a `security-operator`, and
persists provider URL/number, request hash, status, errors, and idempotency
outcomes in `remediation_publications`. Provider tokens remain server-side.

Providers send signed callbacks to `POST /api/dashboard/webhooks/{provider}`
with `x-provider-event-id` and `x-provider-signature`. GitHub and GitLab
secrets are configured separately; duplicate event IDs are accepted without
reprocessing. Merge callbacks persist commit/digest/scan findings and append a
verified or rollback-required timeline event.

Security operators can use `GET
/remediations/publications/{publication_id}/recovery-preview` to inspect stale
status and allowed recovery actions. `POST
/remediations/publications/{publication_id}/recovery` records an idempotent
`request_callback` or `mark_manual_review` request; it never mutates the
provider. `POST /remediations/publications/{publication_id}/evidence` attaches
deployment scan evidence to a merged publication and re-evaluates its healthy
or rollback-required decision.

These endpoints stop before repository mutation. A future execution worker must
consume only approved records and enforce evidence, worktree, validation, and
rollback gates.

For OIDC, an ingress must verify the token before forwarding
`x-authenticated-sub` and optional email/roles headers. The API accepts those
headers only when `x-dashboard-proxy-secret` matches the server-side
`DASHBOARD_TRUSTED_PROXY_SECRET`.
