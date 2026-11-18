# Sign-in through a forward-auth proxy (OIDC)

Status: in progress, step 1 of 3 built (API) · 2026-11-17 · Phase 6

## Problem

The dashboard has no sign-in. In the default `local` mode, anyone who can reach
port 3001 gets `DASHBOARD_DEFAULT_ROLES`, which is usually every role, so they can
approve and publish fixes. That's acceptable on a trusted LAN, but nowhere else.
Audit entries all name the same actor, `dashboard-service`.

A `trusted-proxy` mode exists, but it isn't usable with real tools:

- **Header names are fixed.** The ingress must send `x-authenticated-sub`, `-email`
  and `-roles`. Authelia, Authentik and oauth2-proxy each use their own names, so
  every deployment needs a renaming layer.
- **Group names are role names.** An identity-provider group must be literally
  called `security-operator` to grant that role. There's no mapping.
- **Any signed-in user can read everything.** Read routes need no role, so if the
  identity provider covers more people than the operators (a family Google
  account, a company directory), all of them can browse every vulnerability.
- **Some pages skip the check.** `src/proxy.ts` matches `/dashboard`, `/scans`,
  `/audit`, `/remediations` and `/api`. The menu also links `/images`,
  `/notifications` and `/`, which render their shell without an identity. Their
  data calls still fail with 401.
- **No sign-out.** Users have no way to end the proxy's session from the dashboard.

## Decision: forward-auth, not OIDC in the app

Sign-in happens in a reverse proxy that already speaks OIDC: Authelia, Authentik,
oauth2-proxy or Pomerium, in front of Traefik, Caddy or nginx. Scrutineering
trusts the identity headers that proxy sends, and maps groups to roles itself.

The alternative is OIDC inside the dashboard (Auth.js or similar). That means
login callbacks, session cookies and their encryption keys, token refresh, and
logout, all written and maintained here. A home lab that exposes services
usually runs one of these proxies already, and the same contract works for any
of them. Native OIDC can come later behind the same identity contract (see Open
questions).

## Scope

**In:**

- Header presets for Authelia, Authentik and oauth2-proxy, plus the current
  `x-authenticated-*` names.
- Mapping identity-provider groups to roles (`DASHBOARD_GROUP_ROLES`).
- In `trusted-proxy` mode:
  - a user with no mapped role is refused;
  - the API never falls back to `DASHBOARD_DEFAULT_ROLES`.
- Every page goes through the identity check.
- A sign-out link (`DASHBOARD_LOGOUT_URL`).
- A tested example: Traefik with Authelia (file-backed users), in
  `examples/forward-auth/`.

**Out:**

- OIDC in the app.
- Per-user API tokens for scripts. Scripts keep using the API key against the
  API, which is not exposed.
- User management, and per-image permissions.
- The "multi-user roles" Phase 6 item. This note only maps groups onto the
  existing five roles.

## Design

### The identity contract

```
browser ──▶ ingress ──forward-auth──▶ Authelia / Authentik / oauth2-proxy ──▶ IdP (OIDC)
              │  adds identity headers from the auth response, strips any the client sent,
              │  and adds x-dashboard-proxy-secret
              ▼
           dashboard (src/proxy.ts) ──▶ API (/api/dashboard/...)
```

1. **The ingress authenticates**, through its forward-auth middleware. It must:
   - replace any identity headers the client sent with the auth server's;
   - add `x-dashboard-proxy-secret: <DASHBOARD_TRUSTED_PROXY_SECRET>`.

   The secret proves a request came through the ingress. Without it, someone who
   reaches port 3001 directly could claim to be anyone.
2. **The dashboard reads the preset's headers**, chosen by
   `DASHBOARD_AUTH_HEADERS`:

   | Preset | User | Email | Groups | Separator |
   |---|---|---|---|---|
   | `scrutineering` (default) | `x-authenticated-sub` | `x-authenticated-email` | `x-authenticated-roles` | `,` |
   | `authelia` | `Remote-User` | `Remote-Email` | `Remote-Groups` | `,` |
   | `authentik` | `X-authentik-username` | `X-authentik-email` | `X-authentik-groups` | `\|` |
   | `oauth2-proxy` | `X-Auth-Request-User` | `X-Auth-Request-Email` | `X-Auth-Request-Groups` | `,` |

   It refuses the request (401 for `/api`, a sign-in-required page otherwise)
   unless the secret matches and a user is present. It then forwards the identity
   to the API in the existing `x-authenticated-*` form, with the groups as a
   comma list. The API therefore reads one fixed set of headers.
3. **The API maps groups to roles.** `DASHBOARD_GROUP_ROLES` is a comma list of
   `group=role` pairs, such as
   `scrutineering-admins=admin,security=security-operator,ops=operator`.
   - A user's roles are the union of their groups' roles. Unknown roles fail at
     startup.
   - When the mapping is empty, group names are used as role names, as today.
     The operator guide recommends setting the mapping.
4. **In `trusted-proxy` mode, the API:**
   - refuses `/api/dashboard` requests that carry no verified identity. The
     dashboard's API key alone no longer yields `DASHBOARD_DEFAULT_ROLES`;
   - refuses a user with no role at all, with `403 no_role`. Being signed in to
     the IdP isn't enough to read vulnerability data.

   This requires the API to know the mode, so `DASHBOARD_AUTH_MODE` moves into
   `src/config.py`, read by the API and the dashboard. It is currently listed as
   an external variable read only by the dashboard.
5. **Audit.** `actor` is the user and `actor_kind` is `user`, as the existing
   `oidc_proxy` path already records. The email is added to each entry's detail,
   so the trail is readable when the user ID is opaque.

### Dashboard changes

- `src/proxy.ts` matches every path except Next's static assets and
  `/api/health`.
- The header shows the user's email (or user ID), and **Sign out** when
  `DASHBOARD_LOGOUT_URL` is set (for example,
  `https://auth.home.lan/logout?rd=https://scrutineering.home.lan`).
- A user whose groups map to no role sees a short page saying so, naming the
  setting an administrator changes. It doesn't list the groups.

### What `local` mode keeps

`local` keeps working exactly as today: no sign-in, with
`DASHBOARD_DEFAULT_ROLES`. The cross-site check from #134 protects it from other
sites. The operator guide says plainly that `local` is for a trusted network
only.

## Configuration

| Variable | Default | Read by | Notes |
|---|---|---|---|
| `DASHBOARD_AUTH_MODE` | `local` | api, dashboard | Moves into `src/config.py`; `local` or `trusted-proxy`. |
| `DASHBOARD_AUTH_HEADERS` | `scrutineering` | dashboard | `scrutineering`, `authelia`, `authentik` or `oauth2-proxy`. |
| `DASHBOARD_GROUP_ROLES` | empty | api | `group=role` pairs. Empty means group names are role names. |
| `DASHBOARD_LOGOUT_URL` | empty | dashboard | Sign-out link; hidden when empty. |
| `DASHBOARD_TRUSTED_PROXY_SECRET` | empty | api, dashboard | Unchanged; required in `trusted-proxy` mode. |

## Security

- **Spoofed identity headers** are the main risk. If the ingress passes a
  client's own `Remote-User` through, anyone can claim to be anyone. Defenses:
  - each recipe in the docs configures the ingress to overwrite the identity
    headers. Traefik's `authResponseHeaders` and Caddy's `copy_headers` both
    replace them;
  - the proxy secret means only the ingress can reach the dashboard with an
    identity at all;
  - the operator guide says to expose the dashboard and API ports only to the
    ingress: no published host ports, or published on 127.0.0.1 only;
  - the example's live test sends a forged `Remote-User` through the ingress and
    checks that it's ignored.
- **No fallback.** In `trusted-proxy` mode, a missing or bad identity is a 401,
  never the default roles. Today the API falls back to `DASHBOARD_DEFAULT_ROLES`
  for any request with the API key.
- **Least privilege by default.** A user with no mapped role gets nothing.
- **CSRF.** Forward-auth sessions are cookies, so the cross-site check in
  `src/proxy.ts` (#134) applies, in every mode.
- **Secrets.** The proxy secret stays in the environment, and responses and logs
  never include it.

## Testing

- **API unit tests:**
  - group mapping: union, unknown roles rejected, empty mapping;
  - no fallback to the default roles in `trusted-proxy` mode;
  - `403 no_role`;
  - the email recorded in audit entries;
  - `local` mode unchanged.
- **Dashboard:** the header presets and the identity check are plain functions
  tested with `node --test`, like `sameOrigin.mjs`. The matcher's coverage of
  every page is checked against the app's page directories.
- **Golden path:** unchanged; it runs in `local` mode. A new test runs the
  remediation API calls with a mapped `trusted-proxy` identity, to show the roles
  carry the loop.
- **Live:** `examples/forward-auth/` (Traefik with Authelia and a file-backed
  user list) is brought up next to the stack. The check covers:
  - signing in in Chrome, and the audit actor;
  - refusals: no role, a forged header, a missing secret, direct port access;
  - sign-out.

## Rollout

1. **API** (built):
   - `DASHBOARD_AUTH_MODE` in settings;
   - `DASHBOARD_GROUP_ROLES`;
   - no fallback in `trusted-proxy` mode;
   - `403 no_role`;
   - the email in audit entries;
   - tests and docs.
2. **Dashboard:** header presets, the matcher covering every page, sign-out, the
   no-role page, and tests.
3. **Example and guide:**
   - `examples/forward-auth/`: Traefik with Authelia, tested live;
   - an OPERATOR_GUIDE section, with ingress settings for Traefik, Caddy and
     nginx. Only the Traefik one is tested.

Each step keeps `local` mode and the golden path unchanged.

## Open questions

1. **Native OIDC as well?**
   *Recommendation:* not now. Revisit if someone needs Scrutineering without a
   proxy in front of it.
2. **Which presets?**
   *Recommendation:* Authelia, Authentik and oauth2-proxy, plus the current
   names. Pomerium and Cloudflare Access send signed JWT assertions; trusting
   those means verifying the JWT, which would be a separate step.
3. **A signed-in user with no mapped role:** refuse, or allow read-only access?
   *Recommendation:* refuse. Read access shows every vulnerability in your
   images.
4. **What do you run, or plan to run, in front of it?** The example and the one
   live-tested recipe should match.
   *Recommendation:* Traefik with Authelia, unless you already use something else.
