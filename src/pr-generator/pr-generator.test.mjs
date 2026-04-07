import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import { createRemediationPlan } from "../planner/remediation-planner.mjs";
import { createPullRequestArtifacts } from "./pr-generator.mjs";

function loadSeededPlan() {
  const seededPath = path.resolve("fixtures/planner/seeded-findings.json");
  const seeded = JSON.parse(fs.readFileSync(seededPath, "utf8"));
  return createRemediationPlan(seeded, { dryRun: false });
}

test("per-repo execution creates staged PR artifacts with rollback metadata", () => {
  const plan = loadSeededPlan();
  const result = createPullRequestArtifacts({
    executionMode: "per_repo",
    idempotencyKey: "scan-2026-04-05T06:30:00Z",
    runId: "run-001",
    plan,
    guardrails: {
      maxDiffLines: 120,
      allowlistPaths: ["^services/"],
      denylistPaths: ["^services/.*/secrets\\.env$"],
    },
  });

  assert.equal(result.status, "ready");
  assert.equal(result.gate.status, "pass");
  assert.ok(result.pullRequests.length >= 2);
  assert.ok(result.pullRequests.every((pr) => pr.branch.startsWith("auto/remediate/")));
  assert.ok(result.pullRequests.every((pr) => pr.rollback?.strategy === "git_revert_commit"));
});

test("batched mode produces one aggregate PR envelope", () => {
  const plan = loadSeededPlan();
  const result = createPullRequestArtifacts({
    executionMode: "batched",
    idempotencyKey: "scan-2026-04-05T07:00:00Z",
    runId: "run-002",
    batchRepository: "staging/remediation-batch",
    plan,
    guardrails: {
      maxDiffLines: 120,
      allowlistPaths: ["^services/"],
    },
  });

  assert.equal(result.status, "ready");
  assert.equal(result.pullRequests.length, 1);
  assert.equal(result.pullRequests[0].repository, "staging/remediation-batch");
});

test("guardrails fail closed when denylist is touched", () => {
  const plan = {
    changes: [
      {
        target: { filePath: "services/api/secrets.env", packageName: "dotenv" },
        action: "package_pin_update",
        from: "16.0.0",
        to: "16.0.1",
      },
    ],
  };

  const result = createPullRequestArtifacts({
    executionMode: "per_repo",
    idempotencyKey: "scan-2026-04-05T07:05:00Z",
    runId: "run-003",
    plan,
    guardrails: {
      maxDiffLines: 50,
      allowlistPaths: ["^services/"],
      denylistPaths: ["secrets\\.env$"],
    },
  });

  assert.equal(result.status, "blocked");
  assert.equal(result.gate.status, "fail");
  assert.ok(result.gate.reasonCodes.includes("protected_file_denied"));
  assert.equal(result.pullRequests.length, 0);
});

test("guardrails fail closed when max diff estimate exceeds threshold", () => {
  const plan = loadSeededPlan();
  const result = createPullRequestArtifacts({
    executionMode: "per_repo",
    idempotencyKey: "scan-2026-04-05T07:08:00Z",
    runId: "run-004",
    plan,
    guardrails: {
      maxDiffLines: 10,
      allowlistPaths: ["^services/"],
    },
  });

  assert.equal(result.status, "blocked");
  assert.ok(result.gate.reasonCodes.includes("max_diff_exceeded"));
  assert.equal(result.pullRequests.length, 0);
});

test("retry is idempotent and reuses prior artifact fingerprints", () => {
  const plan = loadSeededPlan();
  const first = createPullRequestArtifacts({
    executionMode: "batched",
    idempotencyKey: "scan-2026-04-05T08:00:00Z",
    runId: "run-005",
    plan,
    guardrails: {
      maxDiffLines: 200,
      allowlistPaths: ["^services/"],
    },
  });

  const second = createPullRequestArtifacts({
    executionMode: "batched",
    idempotencyKey: "scan-2026-04-05T08:00:00Z",
    runId: "run-006",
    plan,
    previousArtifacts: first.pullRequests,
    guardrails: {
      maxDiffLines: 200,
      allowlistPaths: ["^services/"],
    },
  });

  assert.equal(second.status, "ready");
  assert.equal(second.retry.deduplicated, true);
  assert.equal(second.retry.deduplicatedCount, 1);
  assert.equal(second.pullRequests.length, 1);
  assert.equal(second.pullRequests[0].fingerprint, first.pullRequests[0].fingerprint);
  assert.equal(second.pullRequests[0].deduplicated, true);
});
