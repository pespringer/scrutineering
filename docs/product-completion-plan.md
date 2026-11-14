# Product Completion Plan

Scrutineering has a functioning home-lab scan and remediation foundation. The
remaining work is to make the everyday operator journey coherent, repeatable,
and supportable. This plan excludes the three infrastructure gates already
marked deferred in the meaningful milestone plan.

## 1. Complete source onboarding

Make inventory the starting point instead of requiring manual image strings.

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

- Add an environment/readiness center covering database, queue, workers,
  scanner freshness, backups, storage, and configuration drift.
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
