# Authorization Foundation

`src/auth/authorization.mjs` defines the internal authorization boundary used by
future API authentication adapters. A verified identity is represented as a
principal with an ID, roles, and allowed tenant IDs. Handlers can call
`authorize(principal, { role, tenantId })` and map the returned code to the API
error envelope.

The module intentionally does not decode JWTs or trust request headers. An OIDC
or API-gateway adapter must validate signatures, issuer, audience, expiry, and
tenant claims before constructing a principal. Until that adapter is wired into
the planner, the existing API-key boundary remains the only active control.

Run the focused contract tests with:

```bash
node --test src/auth/authorization.test.mjs
```
