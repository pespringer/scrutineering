# Meaningful Product Milestone Plan

## Outcome

Reach a trustworthy home-lab milestone where Scrutineering authenticates
operators, scans real containers, tracks findings over time, recommends useful
fixes, and proves a fix through rescan. Commercial features such as billing,
compliance exports, and automatic merge remain out of scope.

## Current Status

Steps 1–8 are implemented and verified locally for the home-lab scope. The November 14, 2026
acceptance run completed the real scan and runtime-discovery paths, then used
the disposable source fixture to prove signed-evidence verification,
isolated exact-match remediation, ordered validation gates, and a clean
post-change rescan. Remediation guidance now exposes impact, package/CVE/file
coordinates, confidence, and the next operator action. See
[`docs/operations/milestone-acceptance.md`](operations/milestone-acceptance.md)
for commands, evidence, and limitations.

### Deferred infrastructure work

The following are explicitly deferred and are not prerequisites for the local
home-lab milestone. They remain visible as incomplete gates:

- GitHub PR publication and merge-callback verification.
- Deployed image-digest observation and post-merge deployment verification.
- External alert receiver delivery, retry, and dead-letter validation.

#### Re-entry requirements

Return to these items when the required external infrastructure is available:

1. A reachable GitHub test repository with a token that can create/update PRs,
   read workflow results, and receive merge callbacks.
2. A reachable deployment environment that exposes the deployed image digest
   and rollout state to Scrutineering.
3. A configured alert receiver with an authenticated endpoint that retains
   delivery, retry, and dead-letter evidence.

Until then, local providers, signed fixtures, and deterministic replay tests
may validate contracts, but they do not satisfy these live acceptance gates.

## Work Plan Status

1. **Complete — dashboard identity boundary.** Caller-supplied identity
   headers are accepted only with the configured trusted-proxy secret.
2. **Complete — authentication boundary.** Local API-key bootstrap and
   trusted-proxy/OIDC claim mapping enforce read and mutation roles.
3. **Complete — live data boundary.** Production routes do not silently render
   seed findings; missing backend data produces an explicit unavailable state.
4. **Complete — finding lifecycle.** Completed rescans resolve absent findings,
   later observations reopen them, and the API exposes lifecycle timestamps.
5. **Complete — runtime discovery.** Docker/containerd discovery applies the
   configured bounds and queues deduplicated image scans.
6. **Complete — guarded remediation loop.** The disposable fixture acceptance
   run proved evidence verification, isolated edits, ordered validation, and a
   clean rescan.
7. **Complete — remediation guidance.** Findings expose impact, package/CVE/
   file coordinates, fixed versions, confidence, and the next action.
8. **Complete — home-lab acceptance.** Evidence and limitations are recorded
   in the acceptance run and readiness checklist.

### Productization now in progress

- Auditable, expiring finding suppressions with revoke behavior are available.
- Operations health is derived from live Redis, Celery, and backup evidence;
  deferred infrastructure gates are shown separately.
- Per-image scan schedules are durable, bounded, pausable, and visible in the
  image detail workflow.
- Severity-threshold and exact image allow/deny policies are evaluated on
  completed scans and managed from the dashboard.
- Compliance report generation now persists framework evidence snapshots from
  the live posture and audit trail.
- Backup freshness runs now persist idempotent artifact observations, including
  verification state and size, so operations readiness can show durable
  evidence rather than only a process-local timestamp.
- The remaining product work is multi-user source onboarding, richer backup
  backup execution/restore workflow, and end-to-end remediation/provider
  operation. The
  provider publication, deployed-digest, and external-alert items listed
  above remain deferred until their infrastructure is available.

## Definition of Done

- Dashboard access is authenticated and role-aware.
- No production page silently renders seed data.
- A discovered container produces a persisted scan and visible findings.
- Findings close and reopen from subsequent scan results.
- At least one guarded remediation is verified by a clean rescan.
- The acceptance run and any remaining infrastructure-dependent checks are
  documented with reproducible commands.

## Execution Order

Complete steps 1–3 before exposing the dashboard beyond the local machine.
Then implement the finding lifecycle and discovery-to-scan path. The real
remediation loop and acceptance test are the milestone gate; operational and
commercial expansion follows afterward.
