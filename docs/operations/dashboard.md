# Dashboard Operations

`dashboard/` is Scrutineering's only supported frontend. It is a Next.js
application on port 3001 during local development. Docker Compose also builds
and starts it as the `dashboard` service on port 3001. It is built independently
in CI with:

```bash
cd dashboard
npm ci
npm run validate:build
```

CI runs `npm audit --audit-level=high` before the build. Keep direct dependency
versions and `dashboard/package-lock.json` synchronized when applying security
updates; a high or critical advisory blocks the dashboard job.

Run `npm run validate:frontend` from the repository root to verify that the
canonical package and lockfile exist and that the retired frontend tree has
not returned.

Compose and Kubernetes keep `NEXT_PUBLIC_API_URL` empty: browser requests use
same-origin Next.js routes, which proxy server-side to the authenticated Python
API. Configure `DASHBOARD_API_URL` and `DASHBOARD_API_KEY` only in the server
environment. The dashboard should not call internal database, Redis, or scanner
services directly.

For OIDC deployments, the ingress must validate the bearer token and forward
`x-authenticated-sub` plus optional email/roles headers. The dashboard server
adds `DASHBOARD_TRUSTED_PROXY_SECRET` when forwarding that identity context to
the Python API. The API rejects these headers without the matching secret.

## Product surface

The dashboard is organized as a security operations console:

- Overview leads with active exposure, severity trend, risk distribution,
  recent scans, and tracked-image inventory.
- Scan history supports repository search, status filters, outcome counts, and
  runtime details, server-side pagination, targeted scan submission, and
  queued-scan polling.
- Image detail pages provide severity filtering, sortable findings, CVE links,
  fix availability, and responsive layouts.
- The Audit Trail page records scan start/cancel activity with actor context.
- Remediation detail pages show ordered lifecycle events, publication status,
  merge outcomes, and rollback-required decisions.
- Read-only `dashboard` users can inspect data; `operator`,
  `security-operator`, and `admin` roles can start or cancel scans.
- Loading, error, empty, and unavailable-data states are intentional UI states,
  not blank screens.

Run `cd dashboard && npm run build` after visual or route changes. The build
is the release gate for TypeScript correctness and static route generation.
The build also verifies that the generated CSS contains the dashboard utility
bundle; this prevents an unstyled production shell when Tailwind source paths
change.

For a running local stack, use `npm run smoke:dashboard`. It checks the Next.js
browser shell, dashboard proxy routes, and that server-only API credentials are
not present in responses.

Apply the latest database migration before exercising operator actions:

```bash
docker compose exec api alembic -c src/db/migrations/alembic.ini upgrade heads
```

The former `web/` application was removed in Batch 3. New pages, components,
API routes, and visual changes belong under `dashboard/src/`; add a dashboard
build check when changing its routing or dependencies.
