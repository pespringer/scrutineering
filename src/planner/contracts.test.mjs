import assert from "node:assert/strict";
import test from "node:test";
import { validatePlannerRequest } from "./contracts.mjs";

test("validates required fields for every planner route", () => {
  assert.equal(validatePlannerRequest("/v1/plans", { findings: [] }).valid, true);
  assert.equal(validatePlannerRequest("/v1/pull-requests", { idempotencyKey: "run-1", plan: {} }).valid, true);
  assert.equal(validatePlannerRequest("/v1/ci/checks", { checks: [] }).valid, true);
  assert.equal(validatePlannerRequest("/v1/rollout/evaluate", { teamId: "platform", riskLevel: "low" }).valid, true);
});

test("rejects missing, empty, and incorrectly typed fields", () => {
  assert.equal(validatePlannerRequest("/v1/plans", null).valid, false);
  assert.match(validatePlannerRequest("/v1/pull-requests", { plan: {} }).message, /idempotencyKey/);
  assert.match(validatePlannerRequest("/v1/ci/checks", { checks: "nope" }).message, /checks/);
  assert.match(validatePlannerRequest("/v1/rollout/evaluate", { teamId: "", riskLevel: "low" }).message, /teamId/);
});
