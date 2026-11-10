import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { createJwksVerifier, verifyJwsSignature } from "./jwks-verifier.mjs";

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

test("refreshes JWKS when a rotated key is unknown", async () => {
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
  const token = `${encode({ alg: "RS256", kid: "rotated" })}.${encode({ sub: "user-1" })}.sig`;
  let fetches = 0;
  const verify = createJwksVerifier({ jwksUri: "https://issuer.test/keys", fetchImpl: async () => ({ ok: true, async json() { fetches += 1; return { keys: [{ kid: fetches > 1 ? "rotated" : "old" }] }; } }), verifySignature: async () => true });
  assert.equal((await verify(token)).sub, "user-1"); assert.equal(fetches, 2);
});

test("bounds JWKS cache lifetime", () => {
  assert.throws(() => createJwksVerifier({ jwksUri: "https://issuer.test/keys", verifySignature: async () => true, cacheTtlMs: 1 }), /between/);
});

test("verifies an RS256 signature with the built-in JWK verifier", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = publicKey.export({ format: "jwk" });
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
  const signed = `${encode({ alg: "RS256", kid: "real-key" })}.${encode({ sub: "user-1" })}`;
  const signature = sign("RSA-SHA256", Buffer.from(signed), privateKey).toString("base64url");
  const verify = createJwksVerifier({
    jwksUri: "https://issuer.test/keys",
    fetchImpl: async () => ({ ok: true, async json() { return { keys: [{ ...jwk, kid: "real-key", alg: "RS256", use: "sig" }] }; } }),
    verifySignature: verifyJwsSignature,
  });
  assert.equal((await verify(`${signed}.${signature}`)).sub, "user-1");
});
