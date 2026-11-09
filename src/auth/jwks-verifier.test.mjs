import test from "node:test";
import assert from "node:assert/strict";
import { createJwksVerifier } from "./jwks-verifier.mjs";

test("verifies JWT claims against a cached JWKS key", async () => {
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
  const token = `${encode({ alg: "RS256", kid: "key-1" })}.${encode({ sub: "user-1" })}.sig`;
  let fetches = 0;
  const verify = createJwksVerifier({ jwksUri: "https://issuer.test/keys", fetchImpl: async () => { fetches += 1; return { ok: true, async json() { return { keys: [{ kid: "key-1", kty: "RSA" }] }; } }; }, verifySignature: async ({ signature }) => signature === "sig" });
  assert.deepEqual(await verify(token), { sub: "user-1" });
  await verify(token);
  assert.equal(fetches, 1);
});

test("rejects unsigned JWTs", async () => {
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
  const token = `${encode({ alg: "none", kid: "k" })}.${encode({ sub: "user-1" })}.`;
  const verify = createJwksVerifier({ jwksUri: "https://issuer.test/keys", verifySignature: async () => true });
  await assert.rejects(() => verify(token), /insecure/);
});
