# Product coherence guide

Scrutineering follows one operator-visible lifecycle:

```text
discover image → queue scan → run Trivy/Grype → normalize findings
→ prioritize → propose remediation → approve/execute → verify with a rescan
```

## Following a scan

Start a scan from **Scan history**. The scan detail page shows the durable scan
ID, Celery task ID, current phase, timestamps, scanner findings, and any error.
While a worker is active the page refreshes automatically. The dashboard also
shows a “Scan activity in progress” banner.

The worker records both the requested operation and its outcome in the audit
trail. A completed scan also writes the current severity snapshot used by the
trend chart. Existing installations without snapshots are read through the
completed scan history until new snapshots exist.

## Following a finding to resolution

Open a scan’s findings and choose **Propose fixes** for findings with a known
fixed version. The remediation queue then shows the proposal, approval state,
execution state, publication status, and verification evidence. After a fix is
verified, the follow-up scan is the source of truth for the remaining finding
count.

Finding lifecycle is based on the latest complete scan: a finding that is no
longer observed receives `resolved_at` and is excluded from open-risk totals,
severity charts, exports, and new remediation proposals. If the same
fingerprint returns on a later scan, it is reopened automatically. Image detail
and remediation responses expose both open and resolved counts so operators can
tell the difference between “nothing has been scanned” and “the risk is gone.”

## External gates

Provider publication, deployment observation, and live alert delivery are
optional gates. They are intentionally shown as deferred when their provider,
ingress, or receiver configuration is absent. Local scanning, finding triage,
remediation planning, and verification remain usable without those integrations.
