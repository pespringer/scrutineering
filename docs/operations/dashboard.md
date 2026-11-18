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

CI runs `npm audit` and `npm run lint` (ESLint with the Next.js rules,
`eslint.config.mjs`) before the build. A high or critical advisory in a
production dependency blocks the dashboard job. Advisories in dev dependencies
(the lint toolchain) show as a warning on the run instead, because they can have
no fixed release; update them when one appears. Keep direct dependency versions
and `dashboard/package-lock.json` synchronized when applying security updates.

Run `make check` from the repository root to verify, among other things, that
the dashboard package and lockfile exist.

Browser requests use same-origin Next.js routes, which proxy server-side to the authenticated Python
API. Configure `DASHBOARD_API_URL` and `DASHBOARD_API_KEY` only in the server
environment. The dashboard should not call internal database, Redis, or scanner
services directly.

The dashboard always reads live data through the API and shows an
unavailable-data error when the API is missing; there is no demo mode.

For sign-in, set `DASHBOARD_AUTH_MODE=trusted-proxy` on the dashboard and the API
(docs/design/forward-auth.md). The ingress authenticates users through its
forward-auth proxy, passes on the proxy's identity headers, and adds the exact
`x-dashboard-proxy-secret` value. It must overwrite any identity headers that a
client sent. `DASHBOARD_AUTH_HEADERS` says whose headers to read:

| Value | User | Email | Groups |
|---|---|---|---|
| `scrutineering` (default) | `x-authenticated-sub` | `x-authenticated-email` | `x-authenticated-roles` (`,`) |
| `authelia` | `Remote-User` | `Remote-Email` | `Remote-Groups` (`,`) |
| `authentik` | `X-authentik-username` | `X-authentik-email` | `X-authentik-groups` (`\|`) |
| `oauth2-proxy` | `X-Auth-Request-User` | `X-Auth-Request-Email` | `X-Auth-Request-Groups` (`,`) |

Every page and `/api` route except `/api/health` requires the user. Without one,
pages answer 401 with a sign-in message and `/api` routes 401 JSON. A user
whose groups map to no role sees a "No access yet" page. Set
`DASHBOARD_LOGOUT_URL` to show **Sign out** in the header.

`DASHBOARD_GROUP_ROLES` maps the groups to roles (`ops=operator,security=security-operator`).
A signed-in user with no mapped role is refused, and the API never falls back to
`DASHBOARD_DEFAULT_ROLES` in this mode. Audit entries record the user's ID and
email. Keep `DASHBOARD_AUTH_MODE=local` for a trusted network only; it has no sign-in.

## Product surface

The dashboard is organized as a security operations console:

- Overview leads with active exposure, severity trend, risk distribution,
  recent scans, and tracked-image inventory.
- Scans supports repository search, status filters, outcome counts, and
  runtime details, server-side pagination, targeted scan submission, and
  queued-scan polling.
- Image detail pages provide severity filtering, sortable findings, CVE links,
  fix availability, and responsive layouts.
- Audit records operator actions and scan lifecycle events with actor context, and
  links each entry to its scan, image or remediation.
- Remediation detail pages show ordered lifecycle events, the patch and
  candidate image, and the GitHub pull request with its merge outcome.
- State-changing `/api/*` requests from another site are refused with `403`
  (`src/proxy.ts`), in every auth mode. Behind a reverse proxy, forward the
  original `Host` (or set `X-Forwarded-Host`) so same-origin requests from
  browsers that send `Origin` but not `Sec-Fetch-Site` still match.
- Notifications (`security-operator`) shows which channels are configured, the
  recent deliveries with their errors, and **Send test**.
- Read-only `dashboard` users can inspect data; `operator`,
  `security-operator`, and `admin` roles can start or cancel scans.
- Loading, error, empty, and unavailable-data states are intentional UI states,
  not blank screens.

Run `cd dashboard && npm run build` after visual or route changes. The build
is the release gate for TypeScript correctness and static route generation.
The build also verifies that the generated CSS contains the dashboard utility
bundle; this prevents an unstyled production shell when Tailwind source paths
change.

For a running local stack, use `make smoke`. It checks the Next.js
browser shell, dashboard proxy routes, and that server-only API credentials are
not present in responses.

Apply the latest database migration before exercising operator actions:

```bash
docker compose exec api alembic -c src/db/migrations/alembic.ini upgrade heads
```

The former `web/` application was removed in Batch 3. New pages, components,
API routes, and visual changes belong under `dashboard/src/`; add a dashboard
build check when changing its routing or dependencies.
