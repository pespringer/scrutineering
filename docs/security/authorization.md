# Authorization Foundation

`src/auth/authorization.mjs` defines the internal authorization boundary used by
future API authentication adapters. A verified identity is represented as a
principal with an ID, roles, and allowed tenant IDs. Handlers can call
`authorize(principal, { role, tenantId })` and map the returned code to the API
error envelope.

The module intentionally does not decode JWTs or trust request headers. An OIDC
or API-gateway adapter must validate signatures, issuer, audience, expiry, and
tenant claims before constructing a principal.

`PLANNER_API_KEYS_JSON` can provide scoped service identities:

```json
{"ci-key":{"principal":"ci","roles":["ci"],"tenantIds":["tenant-a"]}}
```

Planner, CI, rollout, and tenant-bearing requests are checked against these
claims. OIDC/JWT verification must still happen before claims are imported.

`src/auth/oidc.mjs` provides the claim-policy boundary: a deployment-specific
signature verifier supplies trusted claims, then issuer, audience, expiry, and
activation checks map them into the common principal shape. It does not accept
unsigned or self-decoded JWT payloads.

`loadOidcConfig()` requires `OIDC_ISSUER` and `OIDC_AUDIENCE`, and rejects
non-HTTPS issuers before startup wiring can proceed.

Run the focused contract tests with:

```bash
node --test src/auth/authorization.test.mjs
```
OIDC verification now requires HTTPS discovery, rejects unsigned tokens, selects
JWKS keys by `kid`, refreshes on rotation, and applies bounded clock skew before
mapping claims into the authorization principal.
Internal service requests additionally bind the body and timestamp to a
validated service identity, with replay guards available at the receiver.

## Dashboard proxy trust

The Next.js dashboard only forwards `x-authenticated-sub`,
`x-authenticated-email`, and `x-authenticated-roles` when the incoming request
also carries the exact `DASHBOARD_TRUSTED_PROXY_SECRET`. Direct dashboard
requests therefore cannot manufacture a proxy identity. Configure that secret
only between the external identity proxy and the dashboard; do not expose it
to browser code or client-side environment variables.
