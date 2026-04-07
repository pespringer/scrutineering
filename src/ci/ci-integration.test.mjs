import test from "node:test";
import assert from "node:assert/strict";
import { evaluateCiChecks } from "./ci-integration.mjs";

test("returns required-block when checks are missing", () => {
  const result = evaluateCiChecks({
    provider: "github_actions",
    eventName: "pull_request",
    checks: [],
  });

  assert.equal(result.decision, "required-block");
  assert.equal(result.status, "blocked");
  assert.equal(result.reasons[0].code, "missing_checks");
});

test("returns required-block when required check fails", () => {
  const result = evaluateCiChecks({
    provider: "github_actions",
    eventName: "pull_request",
    checks: [
      { name: "build", status: "success", required: true },
      { name: "security-gate", status: "failed", required: true },
    ],
  });

  assert.equal(result.decision, "required-block");
  assert.equal(result.status, "blocked");
  assert.equal(result.reasons[0].code, "required_check_failed");
});

test("returns manual-approval when required checks are pending", () => {
  const result = evaluateCiChecks({
    provider: "github_actions",
    eventName: "pull_request",
    checks: [
      { name: "build", status: "success", required: true },
      { name: "integration", status: "pending", required: true },
    ],
  });

  assert.equal(result.decision, "manual-approval");
  assert.equal(result.status, "pending");
  assert.equal(result.reasons[0].code, "required_check_pending");
});

test("returns manual-approval for unsupported repo event", () => {
  const result = evaluateCiChecks({
    provider: "github_actions",
    eventName: "issue_comment",
    checks: [{ name: "build", status: "success", required: true }],
  });

  assert.equal(result.decision, "manual-approval");
  assert.equal(result.status, "pending");
  assert.equal(result.reasons[0].code, "unsupported_repo_event");
});

test("returns auto-merge when required checks pass and event is allowed", () => {
  const result = evaluateCiChecks({
    provider: "github_actions",
    eventName: "pull_request",
    checks: [
      { name: "build", status: "success", required: true },
      { name: "security-gate", status: "success", required: true },
      { name: "lint", status: "success", required: false },
    ],
  });

  assert.equal(result.decision, "auto-merge");
  assert.equal(result.status, "ready");
  assert.equal(result.reasons[0].code, "all_required_checks_passed");
});
