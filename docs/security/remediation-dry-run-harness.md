# Remediation Dry-Run Harness

This harness validates the end-to-end remediation flow in dry-run mode:

1. planner
2. PR generation
3. verification gate

## Run

```bash
npm run harness:remediation-dry-run
```

The command is CI-safe and exits non-zero if any fixture assertion fails.

## Fixture Coverage

- `expected-pass`: planner + PR generation + verification all succeed.
- `expected-fail`: planner + PR generation succeed, verification is expected to block on a required CI check failure.
- `expected-pending`: planner + PR generation succeed, verification is expected to wait with `status=pending` and `decision=manual-approval`.
- `expected-policy-fail`: planner + PR generation succeed, verification is expected to block on a failed policy artifact gate.

Fixtures are defined in `fixtures/harness/remediation-dry-run/fixtures.json`.

## Machine-Readable Output

The harness writes summary output to:

- `fixtures/harness/remediation-dry-run/summary.json`

Summary includes per-fixture stage results and full stage payloads (`planner`, `prGeneration`, `verification`) so CI can inspect each stage outcome deterministically.

## Expected Top-Level Summary Shape

```json
{
  "generatedAt": "2026-04-05T09:00:00.000Z",
  "fixtureCount": 4,
  "passCount": 4,
  "failCount": 0,
  "status": "pass",
  "results": []
}
```
