import test from "node:test";
import assert from "node:assert/strict";
import { authenticateRequest } from "./request-auth.mjs";

test("prefers provider verification for bearer tokens", async () => {
  let received;
  const principal = { id: "oidc-user", roles: ["planner"], tenantIds: ["tenant-a"] };
  const result = await authenticateRequest(
    { headers: { authorization: "Bearer signed-token" } },
    { apiKey: "signed-token", oidcVerifier: async (token) => { received = token; return principal; } },
  );
  assert.equal(received, "signed-token");
  assert.deepEqual(result, principal);
});

test("rejects invalid provider tokens without falling back to raw bearer values", async () => {
  const result = await authenticateRequest(
    { headers: { authorization: "Bearer invalid" } },
    { apiKey: "invalid", oidcVerifier: async () => { throw new Error("invalid token"); } },
  );
  assert.equal(result, null);
});

test("keeps API-key authentication available without an OIDC provider", async () => {
  const result = await authenticateRequest(
    { headers: { "x-api-key": "planner-key" } },
    { apiKey: "planner-key" },
  );
  assert.equal(result.id, "api-key-service");
});
