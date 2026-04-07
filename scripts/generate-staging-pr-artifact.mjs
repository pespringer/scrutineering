import fs from "node:fs";
import path from "node:path";
import { createRemediationPlan } from "../src/planner/remediation-planner.mjs";
import { createPullRequestArtifacts } from "../src/pr-generator/pr-generator.mjs";

const seededPath = path.resolve("fixtures/planner/seeded-findings.json");
const outputPath = path.resolve("fixtures/pr-generator/staging-pr-artifact.json");

const seeded = JSON.parse(fs.readFileSync(seededPath, "utf8"));
const plan = createRemediationPlan(seeded, { dryRun: false });

const firstRun = createPullRequestArtifacts({
  executionMode: "per_repo",
  idempotencyKey: "staging-seeded-2026-04-05",
  runId: "staging-run-001",
  plan,
  guardrails: {
    maxDiffLines: 200,
    allowlistPaths: ["^services/"],
    denylistPaths: ["^services/.*/secrets\\.env$"],
  },
});

const secondRun = createPullRequestArtifacts({
  executionMode: "per_repo",
  idempotencyKey: "staging-seeded-2026-04-05",
  runId: "staging-run-002",
  plan,
  previousArtifacts: firstRun.pullRequests,
  guardrails: {
    maxDiffLines: 200,
    allowlistPaths: ["^services/"],
    denylistPaths: ["^services/.*/secrets\\.env$"],
  },
});

const artifact = {
  generatedAt: new Date().toISOString(),
  firstRun,
  secondRun,
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(artifact, null, 2)}\n`);
console.log(outputPath);
