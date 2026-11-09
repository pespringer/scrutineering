import test from "node:test";
import assert from "node:assert/strict";
import { createOidcVerifier } from "./oidc-provider.mjs";

test("composes discovery, JWKS verification, and claim policy", async () => {
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
  const token = `${encode({ alg: "RS256", kid: "k" })}.${encode({ iss: "https://issuer.test", aud: "aud", sub: "u", exp: 4102444800 })}.sig`;
  const verify = await createOidcVerifier({ OIDC_ISSUER: "https://issuer.test", OIDC_AUDIENCE: "aud" }, { fetchImpl: async (url) => ({ ok: true, async json() { return url.endsWith("keys") ? { keys: [{ kid: "k" }] } : { issuer: "https://issuer.test", jwks_uri: "https://issuer.test/keys" }; } }), verifySignature: async () => true });
  assert.equal((await verify(token)).id, "u");
});

test("rejects unreasonable OIDC clock skew", async () => {
  await assert.rejects(() => createOidcVerifier({ OIDC_ISSUER: "https://issuer.test", OIDC_AUDIENCE: "aud", OIDC_LEEWAY_SECONDS: "601" }, { fetchImpl: async () => ({ ok: true, async json() { return { issuer: "https://issuer.test", jwks_uri: "https://issuer.test/keys" }; } }), verifySignature: async () => true }), /between/);
});
