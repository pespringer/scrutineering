# Product Completion Plan

Scrutineering has a functioning home-lab scan and remediation foundation. The
remaining work is to make the everyday operator journey coherent, repeatable,
and supportable. This plan excludes the three infrastructure gates already
marked deferred in the meaningful milestone plan.

## 1. Complete source onboarding

Make inventory the starting point instead of requiring manual image strings.

The runtime discovery slice is complete: the scan worker can return a
redaction-safe Docker/containerd inventory, and the Sources page can poll that
inventory and queue a selected image for scanning. Discovery remains explicit
when `SCAN_RUNTIME_DISCOVERY_ENABLED` is off or the worker has no runtime
access.

- Add a source connection wizard for Docker, Compose, Kubernetes, and OCI
  registries, with readiness checks and actionable errors.
- Discover images with immutable digest, workload, namespace, and ownership
  context; deduplicate them into one inventory.
- Let operators select discovered images, set scan cadence, and launch a
  first scan without copying values between pages.

Done means a new operator can connect one source, see discovered assets, and
start a scan entirely from the dashboard.

## 2. Build the investigation workspace

Turn findings into decisions rather than isolated tables.

The first slice is complete: `/findings` now provides a paginated,
cross-image queue with search, lifecycle, severity, acknowledgement, and fix
availability filters, bulk acknowledgement/assignment/suppression, governed
same-image remediation proposals, export, and direct image links.

- Add filters, saved views, bulk actions, and stable URL state for severity,
  image, package, lifecycle, policy, and owner.
- Show finding history, evidence, affected workloads, fix confidence, and
  related remediations in one detail view.
- Add an explicit state model for open, acknowledged, suppressed, resolved,
  reopened, and policy-exempt findings.

Done means an operator can answer “what changed, what is affected, and what
should I do next?” without leaving the investigation flow.

## 3. Finish the remediation loop

Make a recommended fix safely executable and observable.

- Provide a guided preview, approval, validation progress, and result timeline.
- Persist artifacts, logs, validation failures, rollback instructions, and
  rescan evidence with retention controls.
- Support local commit/export as the default delivery path, with provider
  publication remaining an optional adapter.

Done means every remediation has a durable audit trail and a clear terminal
outcome: verified, blocked, failed, or awaiting operator action.

## 4. Make operations self-explanatory

- The first recovery slice is complete: Operations now lists recent failed
  scans and offers a confirmation-gated bulk retry. Retries create new scan
  records while preserving the failed attempt and its audit history. Worker
  diagnostics now include queue depth plus active, reserved, and scheduled
  task counts per live worker. Operations also shows a bounded, redacted view
  of pending runtime events after the durable replay checkpoint when the event
  store is mounted.

Compose now provisions the shared `runtimeeventdata` volume and wires these
paths explicitly through `RUNTIME_EVENT_STORE_PATH` and
`RUNTIME_REPLAY_CHECKPOINT_PATH`; the worker has read-write access and the API
has read-only access.

- Add an environment/readiness center covering database, queue, workers,
  scanner freshness, backups, storage, and configuration drift.
- Surface incomplete readiness directly on the main dashboard with a one-click
  handoff to the setup checklist so operators do not have to discover setup
  problems by opening Operations manually.
- Add direct control-surface links to incomplete setup checks so the checklist
  leads to the correct operations or source workflow.
- Add runbooks and safe actions for retry, pause, resume, replay, backup
  verification, and retention preview.
- Add alert thresholds, notification preferences, and an incident timeline
  using the existing metrics and audit events.

Done means a user can diagnose a failed scan or worker without reading logs or
guessing which container to restart.

## 5. Harden the shipped product

- Add tenant isolation tests at query and mutation boundaries.
- Add API pagination, rate-limit headers, request correlation, and consistent
  error payloads to every operator-facing route.
- Add upgrade/rollback smoke tests for Compose and Helm, migration backups,
  resource defaults, and a documented disaster-restore rehearsal.
- Add accessibility, responsive-layout, browser smoke, and dependency checks
  to CI.

## Completion gate

Call the product complete for the home-lab release when sections 1–5 pass
their acceptance tests, the dashboard supports the full scan-to-resolution
journey, and the production-readiness checklist clearly separates verified
capabilities from the three deferred external gates.
