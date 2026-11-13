# Platform Hardening

The receiver-independent hardening controls are deliberately fail-closed.

## Lifecycle and recovery

Retention is dry-run and disabled by default. Use `RetentionPolicy` or the
existing Celery retention report before enabling purge. Recovery retries use
bounded exponential delay, terminal attempt limits, lease version checks, and
queue starvation metrics. A queue is considered starved when work is waiting
longer than its configured threshold.

## Remediation execution

Execution must keep evidence verification, approval, exact-match edits, safe
relative paths, bounded command output, timeouts, changed-file limits, and
post-change validation. Failed artifacts should be quarantined for review;
they must not be published automatically.

## Provider and disaster recovery

Provider pages, retry-after values, and response schemas are bounded before
being persisted. Backup manifests use canonical JSON and SHA-256 verification.
Restore drills must validate the manifest before loading records.

## Kubernetes and release checks

`k8s/network-policies.yaml` provides default-deny traffic with explicit service,
DNS, registry, and provider-HTTPS exceptions, while `k8s/pod-security.yaml` enables restricted Pod Security
Admission labels. Validate locally with:

```bash
npm run validate:platform-hardening
npm run validate:deployment
npm run drill:staging-readiness
```

Backup exports can be checked before restore with `npm run backup:manifest`;
the manifest binds the record count and canonical SHA-256 digest to the export.
Run `npm run drill:staging-disaster-recovery` to validate backup rotation,
restore preflight, artifact quarantine expiry, and recovery escalation contracts.

Scan history retention is scheduled as a dry-run report through Celery Beat.
Set `SCAN_PURGE_ENABLED=true` only with an approved retention change and run
the report first; `SCAN_RETENTION_DAYS` defaults to 90 days.

External alert receiver delivery remains disabled and is intentionally not part
of these controls.

The `/operations` dashboard is the receiver-independent production view. It
surfaces the release scorecard and telemetry panel catalog for scan latency,
queue depth, backup freshness, provider health, recovery SLOs, worker health,
configuration drift, tenant capacity, and release health. Its API contract is
`GET /api/dashboard/production-operations`.

Run `npm run drill:operations-execution` to validate the receiver-independent
execution contracts. The drill uses deterministic fixtures and does not run a
destructive backup, restore, provider publication, or external notification.

The production workflow drill (`npm run drill:production-workflows`) adds
receiver-independent verification for live-scan evidence, backup/restore
readiness, provider conformance, post-merge decisions, recovery timing, and
release security checks.

The production maturity drill adds bounded checks for scan orchestration,
backup destinations, provider readiness, database quality, scaling decisions,
identity security, documentation freshness, and promotion evidence. It does
not contact an external alert receiver.
## Scan and backup operations

Scheduled scans suppress images inside `SCAN_COOLDOWN_SECONDS` and report
discovered, queued, and suppressed counts. Stale running scans and scanner
failures are classified for operator review. Configure `BACKUP_ROTATION_KEEP`
and `BACKUP_MAX_AGE_DAYS`, review the dry-run rotation report, and perform
restore drills only against isolated targets.

Bulk dashboard actions are bounded to 100 IDs, require an elevated operator
role, and emit audit events. Scan archiving never touches active work, retry
creates a new scan identity, and finding acknowledgement/assignment never
changes the original scanner evidence.

Provider adapters expose capability diagnostics without returning credentials.
Provider outages are classified as timeout, rate-limited, permission-denied,
not-found, or unavailable. Queue depth, backup freshness, provider outcomes,
and SLO status are emitted as bounded Prometheus series. Run
`npm run drill:receiver-independent-failures` before release promotion.

Remediation retries require an active lease, an approved state, and a recorded
artifact fingerprint. Provider payloads are redacted before diagnostics are
persisted. Database archival, backup deletion, tenant retention, and queue
recovery plans are dry-run or approval-gated by default.
