# Remediation Dry-Run Harness QA Validation Plan

This document defines QA validation gates for [SCR-37](/SCR/issues/SCR-37) using the dry-run remediation harness and current fixture set.

## Scope

Validate the full dry-run chain:

1. planner
2. PR generation
3. verification gate

Primary command:

```bash
npm run harness:remediation-dry-run
```

Generated evidence artifact:

- `fixtures/harness/remediation-dry-run/summary.json`

## Test Matrix

| Scenario | Stage | Assertion | Expected Result |
| --- | --- | --- | --- |
| `expected-pass` | planner | `dryRun=true` and `changes >= 1` | pass |
| `expected-pass` | PR generation | `status=ready` and `pullRequests >= 1` | pass |
| `expected-pass` | verification | `status=ready` and `decision=auto-merge` | pass |
| `expected-fail` | planner | `dryRun=true` and `changes >= 1` | pass |
| `expected-fail` | PR generation | `status=ready` and `pullRequests >= 1` | pass |
| `expected-fail` | verification | `status=blocked` and `decision=required-block` | pass (expected fail-mode behavior) |
| `expected-pending` | planner | `dryRun=true` and `changes >= 1` | pass |
| `expected-pending` | PR generation | `status=ready` and `pullRequests >= 1` | pass |
| `expected-pending` | verification | `status=pending` and `decision=manual-approval` | pass (expected wait-mode behavior) |
| `expected-policy-fail` | planner | `dryRun=true` and `changes >= 1` | pass |
| `expected-policy-fail` | PR generation | `status=ready` and `pullRequests >= 1` | pass |
| `expected-policy-fail` | verification | `status=blocked` and `decision=required-block` | pass (expected policy gate failure behavior) |

Fixture source:

- `fixtures/harness/remediation-dry-run/fixtures.json`

## Gate Criteria

### Overall Harness Gate

- Pass when `summary.status == "pass"`
- Fail when `summary.status != "pass"`

### Stage Gates

- Planner gate pass criteria:
  - `stages.planner.status == "pass"`
  - `stages.planner.dryRun == true`
- PR generation gate pass criteria:
  - `stages.prGeneration.status == "pass"`
  - `stages.prGeneration.gateStatus == "pass"`
  - `stages.prGeneration.pullRequestCount >= 1`
- Verification gate pass criteria per scenario:
  - `expected-pass`: `stages.verification.status == "pass"` and `decision == "auto-merge"`
  - `expected-fail`: `stages.verification.status == "fail"` and `decision == "required-block"`
  - `expected-pending`: `stages.verification.status == "fail"` and `decision == "manual-approval"`
  - `expected-policy-fail`: `stages.verification.status == "fail"` and `decision == "required-block"`

### Verification Policy Sub-Gates

For pass-path validation, all of the following must be `pass`:

- `policyGateStatus`
- `exceptionGateStatus`
- `reproducibilityStatus`

Required CI checks that must remain enforced:

- `dependency_scan`
- `container_image_scan`
- `static_analysis`
- `secrets_detection`
- `verification_harness_health`
- `regression_scope`

## Repro Checklist

### Environment Prerequisites

- Node.js + npm available in workspace
- Dependencies installed (`npm install`)
- Fixture files present:
  - `fixtures/planner/seeded-findings.json`
  - `fixtures/harness/remediation-dry-run/fixtures.json`

### One-Command Repro

```bash
npm run harness:remediation-dry-run
```

Expected command behavior:

- exits `0`
- writes/updates `fixtures/harness/remediation-dry-run/summary.json`
- summary contains:
  - `fixtureCount=4`
  - `passCount=4`
  - `failCount=0`
  - `status=pass`

## Current Evidence Snapshot

Run timestamp (from summary): `2026-04-05T09:00:00.000Z`

Observed outcomes:

- `expected-pass`: planner=pass, prGeneration=pass, verification=pass (`auto-merge`)
- `expected-fail`: planner=pass, prGeneration=pass, verification=fail (`required-block`) as expected
- `expected-pending`: planner=pass, prGeneration=pass, verification=fail (`manual-approval`) as expected
- `expected-policy-fail`: planner=pass, prGeneration=pass, verification=fail (`required-block`) as expected

## Remaining Question

1. Owner: Coder (`SCR-37`)
   - Question: Should unsupported planner findings above a threshold (for example coverage below 90%) block verification by policy, or remain advisory only?
   - Request: Confirm intended gate semantics so QA can lock final release criteria.
