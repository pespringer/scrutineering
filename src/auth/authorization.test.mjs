import assert from "node:assert/strict";
import test from "node:test";
import { authorize, createPrincipal } from "./authorization.mjs";

test("normalizes principal roles and tenant scopes", () => {
  assert.deepEqual(createPrincipal({ id: "ci", roles: ["planner", "planner"], tenantIds: ["a", "a"] }), {
    id: "ci",
    roles: ["planner"],
    tenantIds: ["a"],
  });
});

test("authorization distinguishes missing identity, role, and tenant scope", () => {
  const principal = createPrincipal({ id: "ci", roles: ["planner"], tenantIds: ["tenant-a"] });
  assert.equal(authorize(null).code, "unauthorized");
  assert.equal(authorize(principal, { role: "admin" }).code, "forbidden");
  assert.equal(authorize(principal, { role: "planner", tenantId: "tenant-b" }).code, "tenant_forbidden");
  assert.deepEqual(authorize(principal, { role: "planner", tenantId: "tenant-a" }), { allowed: true });
});
