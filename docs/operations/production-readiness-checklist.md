# Production Readiness Checklist: Automated Remediation Rollout

- Owner: Founding Engineer (DevEx)
- Last Updated: 2026-11-10
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

## 6. Staging Readiness and Observability

- Run `npm run drill:staging-readiness` and retain its output with the release
  record. This validates schema targets, authenticated service replay
  protection, shared cache delivery, audit anchoring, release evidence, and
  monitoring asset coverage.
- Run the same checks against the deployed staging environment with real
  PostgreSQL, Redis, OIDC/Cosign credentials, and alert receivers.
- Confirm Prometheus evaluates the scan failure, scan P95 latency, and runtime
  dead-letter alerts, and that the Grafana dashboard receives current data.
- Confirm health/readiness endpoints, resource quotas, pod disruption budgets,
  and database migrations are green after deployment.

## 7. Go/No-Go Gate

Go live only when all of the following are true:

- All tests pass in CI for the rollout branch.
- Staging rollback drill completed and documented.
- Deterministic readiness drill and live staging smoke checks completed.
- Monitoring dashboards and alert delivery verified with current staging data.
- On-call playbook has named primary/secondary responders.
- Kill switch ownership and paging route are confirmed.
## Staging promotion gates

- Run `npm run verify:local`.
- Run `npm run drill:staging-rollback`.
- Run `npm run validate:release` with production values and
  `npm run drill:staging-evidence`; confirm invalid provider, identity, and
  stale-evidence scenarios block promotion.
- Confirm OIDC issuer, cosign identity, provider allowlists, and service secrets
  are configured from the deployment secret store.
- Confirm release assets include planner/worker Cosign signatures and
  certificates before publishing the tag.
- Confirm database pool bounds, resource quotas, and pod disruption budgets are
  applied before enabling production scan concurrency.
- Run `npm run validate:deployment` after changing any image, Compose, or
  Kubernetes manifest.
