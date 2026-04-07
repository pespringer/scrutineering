import path from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import { runRemediationDryRunHarness } from "./remediation-dry-run-harness.mjs";

test("end-to-end dry-run harness validates pass, fail, pending, and policy-fail fixtures", () => {
  const projectRoot = path.resolve(".");
  const result = runRemediationDryRunHarness({
    projectRoot,
    fixturesPath: "fixtures/harness/remediation-dry-run/fixtures.json",
    now: "2026-04-05T09:00:00.000Z",
  });

  assert.equal(result.status, "pass");
  assert.equal(result.fixtureCount, 4);
  assert.equal(result.passCount, 4);
  assert.equal(result.failCount, 0);

  const passFixture = result.results.find((entry) => entry.fixture === "expected-pass");
  const failFixture = result.results.find((entry) => entry.fixture === "expected-fail");
  const pendingFixture = result.results.find((entry) => entry.fixture === "expected-pending");
  const policyFailFixture = result.results.find((entry) => entry.fixture === "expected-policy-fail");

  assert.ok(passFixture);
  assert.ok(failFixture);
  assert.ok(pendingFixture);
  assert.ok(policyFailFixture);

  assert.equal(passFixture.stages.planner.status, "pass");
  assert.equal(passFixture.stages.prGeneration.status, "pass");
  assert.equal(passFixture.stages.verification.status, "pass");

  assert.equal(failFixture.stages.planner.status, "pass");
  assert.equal(failFixture.stages.prGeneration.status, "pass");
  assert.equal(failFixture.stages.verification.status, "fail");
  assert.equal(failFixture.outputs.verification.status, "blocked");
  assert.equal(failFixture.outputs.verification.decision, "required-block");

  assert.equal(pendingFixture.stages.planner.status, "pass");
  assert.equal(pendingFixture.stages.prGeneration.status, "pass");
  assert.equal(pendingFixture.stages.verification.status, "fail");
  assert.equal(pendingFixture.outputs.verification.status, "pending");
  assert.equal(pendingFixture.outputs.verification.decision, "manual-approval");
  assert.equal(pendingFixture.outputs.verification.verificationSummary.policyGateStatus, "pass");
  assert.equal(pendingFixture.outputs.verification.verificationSummary.exceptionGateStatus, "pass");
  assert.equal(pendingFixture.outputs.verification.verificationSummary.reproducibilityStatus, "pass");
  assert.ok(
    pendingFixture.outputs.verification.gates.some(
      (gate) => gate.name === "ci_required_checks" && gate.reasonCodes.includes("required_check_pending"),
    ),
  );

  assert.equal(policyFailFixture.stages.planner.status, "pass");
  assert.equal(policyFailFixture.stages.prGeneration.status, "pass");
  assert.equal(policyFailFixture.stages.verification.status, "fail");
  assert.equal(policyFailFixture.outputs.verification.status, "blocked");
  assert.equal(policyFailFixture.outputs.verification.decision, "required-block");
  assert.equal(policyFailFixture.outputs.verification.verificationSummary.policyGateStatus, "fail");
  assert.ok(
    policyFailFixture.outputs.verification.gates.some(
      (gate) => gate.name === "policy_artifact" && gate.reasonCodes.includes("policy_result_failed"),
    ),
  );
});

test("dry-run harness output is deterministic across repeated runs", () => {
  const projectRoot = path.resolve(".");
  const input = {
    projectRoot,
    fixturesPath: "fixtures/harness/remediation-dry-run/fixtures.json",
    now: "2026-04-05T09:00:00.000Z",
  };

  const firstRun = runRemediationDryRunHarness(input);
  const secondRun = runRemediationDryRunHarness(input);

  assert.deepEqual(secondRun, firstRun);
});
