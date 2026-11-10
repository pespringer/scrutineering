# Dashboard Operations

`dashboard/` is Scrutineering's only supported frontend. It is a Next.js
application on port 3001 during local development and is built independently
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
not served behind the same origin as the control plane. The dashboard uses the
versioned scan-data routes and should not call internal database or scanner
services directly.

The former `web/` application was removed in Batch 3. New pages, components,
API routes, and visual changes belong under `dashboard/src/`; add a dashboard
build check when changing its routing or dependencies.
