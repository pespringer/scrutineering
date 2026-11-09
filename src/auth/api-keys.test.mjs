import assert from "node:assert/strict";
import test from "node:test";
import { authenticateApiKey, authorizeApiRequest, parseApiKeys } from "./api-keys.mjs";

test("maps configured API keys to scoped principals", () => {
  const keys = parseApiKeys(JSON.stringify({ secret: { principal: "ci", roles: ["ci"], tenantIds: ["tenant-a"] } }));
  const principal = authenticateApiKey("secret", { apiKeys: keys });
  assert.equal(principal.id, "ci");
  assert.equal(authorizeApiRequest(principal, { role: "ci", tenantId: "tenant-a" }).allowed, true);
  assert.equal(authorizeApiRequest(principal, { role: "planner" }).code, "forbidden");
  assert.equal(authorizeApiRequest(principal, { role: "ci", tenantId: "tenant-b" }).code, "tenant_forbidden");
});
