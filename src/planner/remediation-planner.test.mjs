import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import { createRemediationPlan, getSupportedVulnerabilityClasses } from "./remediation-planner.mjs";

function loadSeededFindings() {
  const file = path.resolve("fixtures/planner/seeded-findings.json");
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

test("planner output is deterministic regardless of input order", () => {
  const seeded = loadSeededFindings();
  const forward = createRemediationPlan(seeded, { dryRun: true });
  const reversed = createRemediationPlan(
    { findings: [...seeded.findings].reverse() },
    { dryRun: true },
  );

  assert.deepEqual(reversed, forward);
  assert.equal(forward.summary.deterministicOrdering, true);
});

test("dry-run mode returns no write actions", () => {
  const seeded = loadSeededFindings();
  const plan = createRemediationPlan(seeded, { dryRun: true });

  assert.equal(plan.dryRun, true);
  assert.equal(plan.writeActions.length, 0);
  assert.ok(plan.changes.length > 0);
  assert.ok(plan.changes.every((change) => change.mode === "dry_run"));
});

test("apply mode produces write actions and explainability payload", () => {
  const seeded = loadSeededFindings();
  const plan = createRemediationPlan(seeded, { dryRun: false });

  assert.equal(plan.dryRun, false);
  assert.equal(plan.writeActions.length, plan.changes.length);
  assert.ok(
    plan.writeActions.every(
      (change) =>
        change.explainability &&
        change.explainability.evidence &&
        change.explainability.selectedAction &&
        change.explainability.fallbackAction,
    ),
  );
});

test("conflict handling picks highest-priority fix deterministically", () => {
  const seeded = loadSeededFindings();
  const plan = createRemediationPlan(seeded, { dryRun: true });

  assert.ok(plan.conflicts.length >= 2);

  const lodashChange = plan.changes.find(
    (change) =>
      change.target.filePath === "services/api/package.json" &&
      change.target.packageName === "lodash",
  );

  assert.ok(lodashChange);
  assert.equal(lodashChange.to, "4.17.21");

  const dockerConflict = plan.conflicts.find((conflict) =>
    conflict.target.includes("services/worker/Dockerfile:base_image"),
  );
  assert.ok(dockerConflict);
  assert.equal(dockerConflict.winnerFindingId, "F-005");
});

test("seeded corpus covers at least 90% of known vulnerability classes", () => {
  const seeded = loadSeededFindings();
  const plan = createRemediationPlan(seeded, { dryRun: true });

  assert.ok(plan.summary.coverage >= 0.9);

  const supportedClasses = new Set(getSupportedVulnerabilityClasses());
  const classesInCorpus = new Set(seeded.findings.map((finding) => finding.vulnerabilityClass));
  const coveredClassCount = [...classesInCorpus].filter((cls) => supportedClasses.has(cls)).length;
  const classCoverage = coveredClassCount / classesInCorpus.size;

  assert.ok(classCoverage >= 0.9);
});
