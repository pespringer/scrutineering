import test from "node:test";
import assert from "node:assert/strict";
import { runVerificationHarness } from "./verification-harness.mjs";

function createBaseInput() {
  return {
    now: "2026-04-05T06:45:00.000Z",
    provider: "github_actions",
    prArtifacts: {
      pullRequests: [
        { repository: "api", branch: "auto/remediate/api/abc12345", fingerprint: "abc12345" },
        { repository: "worker", branch: "auto/remediate/worker/def67890", fingerprint: "def67890" },
      ],
    },
    ciByRepository: {
      api: [
        { name: "dependency_scan", status: "success", required: true },
        { name: "container_image_scan", status: "success", required: true },
        { name: "static_analysis", status: "success", required: true },
        { name: "secrets_detection", status: "success", required: true },
        { name: "verification_harness_health", status: "success", required: true },
        { name: "regression_scope", status: "success", required: true },
      ],
      worker: [
        { name: "dependency_scan", status: "success", required: true },
        { name: "container_image_scan", status: "success", required: true },
        { name: "static_analysis", status: "success", required: true },
        { name: "secrets_detection", status: "success", required: true },
        { name: "verification_harness_health", status: "success", required: true },
        { name: "regression_scope", status: "success", required: true },
      ],
    },
    policyArtifact: {
      attached: true,
      status: "pass",
    },
    baselineMetrics: {
      truePositives: 188,
      falsePositives: 6,
      trueNegatives: 204,
      falseNegatives: 2,
    },
    reproducibleRuns: 2,
    exceptions: [],
  };
}

test("returns ready with auditable per-PR artifacts when all gates pass", () => {
  const result = runVerificationHarness(createBaseInput());

  assert.equal(result.status, "ready");
  assert.equal(result.decision, "auto-merge");
  assert.equal(result.pullRequests.length, 2);
  assert.equal(result.pullRequests[0].verificationArtifact.repository, "api");
  assert.equal(result.pullRequests[0].verificationArtifact.gate.status, "pass");
  assert.ok(result.baselineMetrics.precision > 0.9);
  assert.ok(result.baselineMetrics.recall > 0.9);
});

test("blocks when a required check fails for a generated PR", () => {
  const input = createBaseInput();
  input.ciByRepository.worker[1].status = "failed";

  const result = runVerificationHarness(input);
  assert.equal(result.status, "blocked");
  assert.equal(result.decision, "required-block");
  assert.ok(
    result.gates.some(
      (gate) => gate.name === "ci_required_checks" && gate.reasonCodes.includes("required_check_failed"),
    ),
  );
});

test("blocks when policy artifact is missing or reproducibility requirement is not met", () => {
  const input = createBaseInput();
  input.policyArtifact = { attached: false, status: "pass" };
  input.reproducibleRuns = 1;

  const result = runVerificationHarness(input);
  assert.equal(result.status, "blocked");
  assert.ok(result.gates.some((gate) => gate.reasonCodes.includes("missing_policy_result_artifact")));
  assert.ok(result.gates.some((gate) => gate.reasonCodes.includes("insufficient_reproducible_runs")));
});

test("blocks when an exception violates CTO policy controls", () => {
  const input = createBaseInput();
  input.exceptions = [
    {
      id: "EX-001",
      findingId: "F-001",
      severity: "critical",
      confirmedExploitable: true,
      approvedBy: "dev_manager",
      hasCompleteEvidence: false,
      owner: "",
      expiresAt: "2026-04-04T00:00:00.000Z",
    },
  ];

  const result = runVerificationHarness(input);
  assert.equal(result.status, "blocked");
  const exceptionGate = result.gates.find((gate) => gate.name === "exception_policy");
  assert.equal(exceptionGate.status, "fail");
  assert.ok(exceptionGate.reasonCodes.includes("exception_expired"));
  assert.ok(exceptionGate.reasonCodes.includes("exception_invalid_approver"));
  assert.ok(exceptionGate.reasonCodes.includes("exception_missing_evidence"));
  assert.ok(exceptionGate.reasonCodes.includes("exception_critical_exploitable_denied"));
});
