import test from "node:test";
import assert from "node:assert/strict";
import { discoverOidcProvider } from "./oidc-discovery.mjs";

test("loads and validates OIDC discovery metadata", async () => {
  const result = await discoverOidcProvider({ issuer: "https://issuer.test", fetchImpl: async () => ({ ok: true, async json() { return { issuer: "https://issuer.test", jwks_uri: "https://issuer.test/keys" }; } }) });
  assert.equal(result.jwksUri, "https://issuer.test/keys");
});

test("rejects mismatched discovery issuer", async () => {
  await assert.rejects(() => discoverOidcProvider({ issuer: "https://issuer.test", fetchImpl: async () => ({ ok: true, async json() { return { issuer: "https://other.test", jwks_uri: "https://other.test/keys" }; } }) }), /invalid/);
});

test("rejects insecure JWKS endpoints", async () => {
  await assert.rejects(() => discoverOidcProvider({ issuer: "https://issuer.test", fetchImpl: async () => ({ ok: true, async json() { return { issuer: "https://issuer.test", jwks_uri: "http://issuer.test/keys" }; } }) }), /invalid/);
});
