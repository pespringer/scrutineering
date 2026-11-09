import assert from "node:assert/strict";
import test from "node:test";
import { loadOidcConfig } from "./oidc-config.mjs";

test("loads strict HTTPS OIDC configuration", () => {
  assert.deepEqual(loadOidcConfig({ OIDC_ISSUER: "https://issuer.example/", OIDC_AUDIENCE: "scrutineering" }), { issuer: "https://issuer.example", audience: "scrutineering" });
});

test("rejects missing or insecure OIDC configuration", () => {
  assert.throws(() => loadOidcConfig({}), /required/);
  assert.throws(() => loadOidcConfig({ OIDC_ISSUER: "http://issuer", OIDC_AUDIENCE: "x" }), /HTTPS/);
});
