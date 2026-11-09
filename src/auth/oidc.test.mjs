import assert from "node:assert/strict";
import test from "node:test";
import { validateOidcClaims, verifyOidcToken } from "./oidc.mjs";

const claims = { sub: "user-1", iss: "https://issuer", aud: "scrutineering", exp: 2_000_000_000, roles: ["planner"], tenant_ids: ["tenant-a"] };

test("validates OIDC issuer, audience, expiry, and maps claims", () => {
  const principal = validateOidcClaims(claims, { issuer: claims.iss, audience: claims.aud, now: 1_900_000_000_000 });
  assert.deepEqual(principal, { id: "user-1", roles: ["planner"], tenantIds: ["tenant-a"] });
});

test("rejects invalid OIDC claims and token verifier failures", async () => {
  assert.throws(() => validateOidcClaims({ ...claims, iss: "wrong" }, { issuer: claims.iss, audience: claims.aud }), /issuer/);
  assert.throws(() => validateOidcClaims({ ...claims, exp: 1 }, { audience: claims.aud, now: 2_000_000_000_000 }), /expired/);
  await assert.rejects(() => verifyOidcToken("token", async () => ({ ...claims, aud: "other" }), { audience: claims.aud }), /audience/);
});
