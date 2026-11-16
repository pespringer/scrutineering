# Repository Guidelines

## Project Structure & Module Organization

Scrutineering is a Python backend with a Next.js dashboard:

- `src/api` composes the FastAPI app. Dashboard routes live in `src/api/routes/<area>.py` (scans, images,
  findings, remediations, audit, session, posture, webhooks), request bodies in `src/api/schemas.py`, and
  response shapes in `src/api/serializers.py`. Keep each route module under about 400 lines.
- `src/scan`, `src/remediation`, `src/db`, and `src/telemetry` contain the scan workers, remediation pipeline,
  models and migrations, and metrics. `src/scan/discovery` lists running containers for discovery scans.
- `tests/` holds the Python suite; `fixtures/` holds deterministic test data.
- `dashboard/` is the Next.js frontend. Deployment manifests live in `k8s/` and observability
  configuration in `monitoring/`. `scripts/` holds repository checks (with tests in `scripts/tests/`),
  smoke tests, and operational scripts.

## Build, Test, and Development Commands

Python dependencies come from `requirements.txt` (run through `uv`). Use the Makefile:

```bash
make test         # Python tests plus repository checks
make test-python  # pytest tests/
make check        # doc links, deployment manifests, frontend layout, release config
make fmt-check    # Ruff and Prettier (advisory until Phase 3)
make e2e          # golden path against the running stack, real scanners
make up           # docker compose up --build -d
make migrate      # apply Alembic migrations in the api container
```

Run the frontend locally with `cd dashboard && npm run dev`; build it with `npm run build`.

## Coding Style & Naming Conventions

Use four-space indentation for Python and the existing two-space JavaScript/TypeScript style. Follow standard `snake_case` for Python modules, functions, and variables; use `camelCase` for JavaScript functions and variables; use `PascalCase` for classes and React components. Keep repository scripts as `.mjs`, Python packages importable from `src`, and TypeScript types in the frontend `src/types` directories. Format with Ruff (`ruff.toml`) and Prettier (`dashboard/.prettierrc.json`).

## Testing Guidelines

Python tests use `pytest` and are named `tests/test_*.py`; repository-check tests use the built-in `node:test` runner and live in `scripts/tests/*.test.mjs`. Add regression coverage for scanner parsing, finding lifecycle, migrations, and remediation behavior when changing those areas. Keep fixtures deterministic and avoid requiring live Trivy, Grype, databases, or external services in unit tests.

## Commit & Pull Request Guidelines

Recent commits use short, imperative descriptions (for example, `Add full project source code and configuration`). Keep commits focused and explain the user-visible or operational impact. Pull requests should include a concise summary, tests run, affected services or migrations, configuration changes, and screenshots for dashboard changes. Link the relevant issue or design document when applicable; call out security-sensitive behavior and deployment risks explicitly.

## Security & Configuration

Copy `.env.example` to `.env` for local settings and never commit credentials, generated reports, or real vulnerability data. For production-impacting changes, review the Docker, Kubernetes, migration, and security-scan paths in `.github/workflows/ci.yml`.

## Reset Rules (in force until docs/RESET-PLAN.md is complete)

The project is being cut back to its core loop: push or discover an image →
scan → track findings → propose a fix → build a patched image → rescan → open
a PR → mark resolved. Work only on the current phase of
[docs/RESET-PLAN.md](docs/RESET-PLAN.md).

1. The golden-path test (`tests/e2e/test_golden_path.py`, live: `make e2e`)
   defines "working". A change that breaks it does not merge, even if every
   other test passes. When the remediation half starts passing, remove its
   `xfail(strict=True)` marker in the same change.
2. Do not add a top-level module, service, environment variable, or npm/Make
   target unless the current phase calls for it.
3. Keep one status field per entity. Event tables record history; never derive
   current state from them.
4. The server verifies facts itself. Never accept client-asserted verification
   such as `evidence_verified`, finding counts, or digests posted from the browser.
5. No line over 120 characters. Use Prettier for `dashboard/` (`dashboard/.prettierrc.json`)
   and Ruff for Python (`ruff.toml`). Never write a component or function on one line.
6. Docs describe the current system only. Put history in commit messages, not
   in the README or guides.
