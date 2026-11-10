# Production Readiness Checklist: Automated Remediation Rollout

- Owner: Founding Engineer (DevEx)
- Last Updated: 2026-04-05
- Scope: CI-provider integration, staged rollout controls, rollback readiness, and incident operations.

## 1. CI Provider and Repo Event Integration

- `POST /v1/ci/checks` is wired to evaluate required checks from the primary CI provider (`github_actions`).
- Required checks are mapped to merge outcomes:
  - failed required checks -> `required-block`
  - pending required checks -> `manual-approval`
  - all required checks passed on allowlisted repo events -> `auto-merge`
- Allowed repo event triggers are validated:
  - `pull_request`
  - `pull_request_target`
  - `workflow_dispatch`
  - `schedule`
  - `push`
- Unsupported events fail closed to `manual-approval`.

## 2. Staged Rollout Controls

- `POST /v1/rollout/evaluate` enforces team-level controls before automated merge.
- Team rollout allowlist is configurable (`rollout.teamAllowlist`).
- Global kill switch is respected (`rollout.killSwitchEnabled`).
- Hourly rate limit is enforced (`rollout.maxRunsPerHour`).
- Risk-tier escalation is enforced (`rollout.requireManualApprovalRiskAtOrAbove`).

## 3. Rollback and Safety

- PR artifacts include rollback strategy (`git_revert_commit`) and verification guidance.
- Rollout decisions are explicit and auditable (`auto-merge`, `manual-approval`, `required-block`).
- Guardrails are fail-closed for missing checks, failed checks, disallowed teams, and rate-limit violations.

## 4. Verification and Testing

- Unit test coverage includes:
  - CI required-check failure/pending/pass paths.
  - Repo trigger allowlist enforcement.
  - Kill switch behavior.
  - Team allowlist enforcement.
  - Rate-limit enforcement.
  - Risk-tier manual approval routing.
- Execute verification suite:

```bash
npm test
```

## 5. Staging Rollback Drill

- Trigger a simulated remediation run in staging.
- Force a `required-block` path (e.g., failed required check) and confirm no auto-merge action is produced.
- Force a kill switch event and confirm rollout is blocked.
- Disable kill switch, re-run checks, and verify expected `auto-merge` only for allowlisted teams under rate threshold.
- Exercise rollback flow by reverting staged merge commit and re-running verifier checks.

## 6. Go/No-Go Gate

Go live only when all of the following are true:

- All tests pass in CI for the rollout branch.
- Staging rollback drill completed and documented.
- On-call playbook has named primary/secondary responders.
- Kill switch ownership and paging route are confirmed.
## Staging promotion gates

- Run `npm run verify:local`.
- Run `npm run drill:staging-rollback`.
- Confirm OIDC issuer, cosign identity, provider allowlists, and service secrets
  are configured from the deployment secret store.
- Confirm database pool bounds, resource quotas, and pod disruption budgets are
  applied before enabling production scan concurrency.
- Run `npm run validate:deployment` after changing any image, Compose, or
  Kubernetes manifest.
