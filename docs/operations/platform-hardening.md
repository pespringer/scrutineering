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
## Scan and backup operations

Scheduled scans suppress images inside `SCAN_COOLDOWN_SECONDS` and report
discovered, queued, and suppressed counts. Stale running scans and scanner
failures are classified for operator review. Configure `BACKUP_ROTATION_KEEP`
and `BACKUP_MAX_AGE_DAYS`, review the dry-run rotation report, and perform
restore drills only against isolated targets.
