# Dashboard Operations

`dashboard/` is Scrutineering's only supported frontend. It is a Next.js
application on port 3001 during local development. Docker Compose also builds
and starts it as the `dashboard` service on port 3001. It is built independently
in CI with:

```bash
cd dashboard
npm ci
npm run build
```

CI runs `npm audit --audit-level=high` before the build. Keep direct dependency
versions and `dashboard/package-lock.json` synchronized when applying security
updates; a high or critical advisory blocks the dashboard job.

Run `npm run validate:frontend` from the repository root to verify that the
canonical package and lockfile exist and that the retired frontend tree has
not returned.

Set `NEXT_PUBLIC_API_URL` to the reachable API origin when the dashboard is
not served behind the same origin as the control plane. The Compose default is
empty so the dashboard uses its local `/api` routes; set this value at image
build time only when deploying a separate API-backed frontend. The dashboard
should not call internal database or scanner services directly.

## Product surface

The dashboard is organized as a security operations console:

- Overview leads with active exposure, severity trend, risk distribution,
  recent scans, and tracked-image inventory.
- Scan history supports repository search, status filters, outcome counts, and
  runtime details.
- Image detail pages provide severity filtering, sortable findings, CVE links,
  fix availability, and responsive layouts.
- Loading, error, empty, and unavailable-data states are intentional UI states,
  not blank screens.

Run `cd dashboard && npm run build` after visual or route changes. The build
is the release gate for TypeScript correctness and static route generation.

The former `web/` application was removed in Batch 3. New pages, components,
API routes, and visual changes belong under `dashboard/src/`; add a dashboard
build check when changing its routing or dependencies.
