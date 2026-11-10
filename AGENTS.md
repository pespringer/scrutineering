# Repository Guidelines

## Project Structure & Module Organization

Scrutineering combines Node.js orchestration with Python scanning services:

- `src/planner`, `src/ci`, `src/pr-generator`, `src/harness`, `src/verification`, `src/rollout`, and `src/telemetry` contain Node.js modules and `.mjs` tests.
- `src/scan`, `src/runtime`, `src/risk`, `src/forensics`, `src/analytics`, and `src/db` contain Python services, models, and migrations.
- `tests/` holds the Python suite; `fixtures/` holds deterministic test data.
- `dashboard/` is the supported Next.js frontend. Deployment manifests live in `k8s/`, observability configuration in `monitoring/`, and policy contracts in `schemas/`.

## Build, Test, and Development Commands

Install dependencies with `npm ci` and `pip install -r requirements.txt`. Run the full suites with `npm test` and `pytest tests/ -v`. Useful focused commands include:

```bash
node --test "src/**/*.test.mjs"
node scripts/validate-policy-contract.mjs
node scripts/run-remediation-dry-run-harness.mjs
docker compose up --build
```

Run the frontend locally with `cd dashboard && npm run dev`; build it with `npm run build`.

## Coding Style & Naming Conventions

Use four-space indentation for Python and the existing two-space JavaScript/TypeScript style. Follow standard `snake_case` for Python modules, functions, and variables; use `camelCase` for JavaScript functions and variables; use `PascalCase` for classes and React components. Keep Node files as `.mjs`, Python packages importable from `src`, and TypeScript types in the frontend `src/types` directories. No repository-wide formatter or linter is configured, so keep changes consistent with nearby code and run the relevant tests.

## Testing Guidelines

Python tests use `pytest` and are named `tests/test_*.py`; Node tests use the built-in `node:test` runner and are named `*.test.mjs`. Add regression coverage for scanner parsing, policy decisions, migrations, and harness behavior when changing those areas. Keep fixtures deterministic and avoid requiring live Trivy, Grype, databases, or external services in unit tests.

## Commit & Pull Request Guidelines

Recent commits use short, imperative descriptions (for example, `Add full project source code and configuration`). Keep commits focused and explain the user-visible or operational impact. Pull requests should include a concise summary, tests run, affected services or migrations, configuration changes, and screenshots for dashboard changes. Link the relevant issue or design document when applicable; call out security-sensitive behavior and deployment risks explicitly.

## Security & Configuration

Copy `.env.example` to `.env` for local settings and never commit credentials, generated reports, or real vulnerability data. Validate policy changes with `node scripts/validate-policy-contract.mjs`. For production-impacting changes, review the Docker, Kubernetes, migration, and security-scan paths in `.github/workflows/ci.yml`.
