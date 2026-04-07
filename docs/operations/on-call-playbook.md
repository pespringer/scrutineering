# On-Call Playbook: Automated Remediation

- Last Updated: 2026-04-05
- Primary Team: DevEx / Security Platform
- Escalation: Security Incident Commander for active production impact

## Incident Classes

- Class A: Merge Gate Regression
  - Symptoms: valid remediation PRs remain blocked unexpectedly, or invalid PRs become merge-eligible.
  - Impact: remediation throughput disruption or unsafe merges.
- Class B: Rollout Control Failure
  - Symptoms: kill switch ignored, team allowlist bypassed, rate limits not enforced.
  - Impact: uncontrolled production rollout risk.
- Class C: CI Provider Integration Degradation
  - Symptoms: missing check ingestion, stale check state, provider adapter outages.
  - Impact: automation paused or routed to manual approval.

## Triage Steps

1. Confirm incident class from decision payloads (`required-block`, `manual-approval`, `auto-merge`).
2. Collect latest CI check payload and rollout payload from failing request path.
3. Validate expected decision with local reproduction against:
   - `POST /v1/ci/checks`
   - `POST /v1/rollout/evaluate`
4. Determine blast radius:
   - affected teams
   - affected repositories
   - current queued remediation count

## Immediate Containment

- If unsafe merges are possible, enable global kill switch immediately.
- If throughput is blocked but safety is intact, route to `manual-approval` while mitigation is prepared.
- If CI provider signals are stale, freeze auto-merge and require manual approval until freshness recovers.

## Mitigation Runbooks

### A) Merge Gate Regression

- Validate required check status mapping (`success|pending|failed`).
- Validate event trigger allowlist mapping (`pull_request`, `workflow_dispatch`, `schedule`, `push`).
- Patch and redeploy decision service.
- Run staging verification before re-enabling auto-merge.

### B) Rollout Control Failure

- Verify kill switch state source of truth.
- Validate team allowlist and rate-limit config.
- Apply hotfix; rerun control-path tests.
- Keep kill switch enabled until fixed behavior is confirmed.

### C) CI Provider Integration Degradation

- Confirm provider API status and token validity.
- Verify webhook/event delivery health.
- Backfill missed check states if required.
- Keep fallback to manual approval until provider stability window is met.

## Escalation Paths

- P1 (security risk or unsafe merge): page Security IC + CTO immediately.
- P2 (high operational disruption): notify DevEx manager and open incident thread.
- P3 (limited scope, manual fallback available): create fix ticket and schedule within current sprint.

## Exit Criteria

- Decision behavior matches expected outcomes in staging and production smoke checks.
- Kill switch and fallback mode restored to intended steady state.
- Incident timeline, root cause, and prevention actions documented.
