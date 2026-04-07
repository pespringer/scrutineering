import fs from "node:fs";
import path from "node:path";
import { createRemediationPlan } from "../planner/remediation-planner.mjs";
import { createPullRequestArtifacts } from "../pr-generator/pr-generator.mjs";
import { runVerificationHarness } from "../verification/verification-harness.mjs";

const REQUIRED_SECURITY_CHECKS = [
  "dependency_scan",
  "container_image_scan",
  "static_analysis",
  "secrets_detection",
  "verification_harness_health",
  "regression_scope",
];

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function requiredChecks(overrides = {}) {
  const byName = new Map(
    Object.entries(overrides).map(([name, status]) => [name, String(status || "success")]),
  );

  return REQUIRED_SECURITY_CHECKS.map((name) => ({
    name,
    status: byName.get(name) || "success",
    required: true,
  }));
}

function buildCiByRepository(repositories, failedChecks = []) {
  const overrideByRepo = new Map();

  for (let i = 0; i < failedChecks.length; i++) {
    const failedCheck = failedChecks[i];
    const repository = String(failedCheck?.repository ?? "").trim();
    const checkName = String(failedCheck?.name ?? "").trim();
    const status = String(failedCheck?.status ?? "failed").trim();

    if (!repository || !checkName) {
      const missing = !repository ? "repository" : "name";
      throw new Error(
        `failedChecks entry [${i}] is missing required field "${missing}"; ` +
        `malformed scan metadata must not be silently ignored`,
      );
    }

    const current = overrideByRepo.get(repository) || {};
    current[checkName] = status;
    overrideByRepo.set(repository, current);
  }

  return Object.fromEntries(
    repositories.map((repository) => [repository, requiredChecks(overrideByRepo.get(repository) || {})]),
  );
}

function assertStage(condition, stage, message, failures) {
  if (!condition) {
    failures.push({ stage, message });
  }
}

function runFixture(projectRoot, fixture, now) {
  const fixtureName = String(fixture?.name || "unnamed");
  const plannerInputPath = path.resolve(projectRoot, fixture?.plannerInputPath || "");
  const plannerInput = readJson(plannerInputPath);

  const plannerOptions = {
    dryRun: Boolean(fixture?.plannerOptions?.dryRun),
  };

  const plannerResult = createRemediationPlan(plannerInput, plannerOptions);

  const prConfig = fixture?.prInput || {};
  let prResult;
  try {
    prResult = createPullRequestArtifacts({
      executionMode: prConfig.executionMode || "per_repo",
      idempotencyKey: prConfig.idempotencyKey || `dry-run-${fixtureName}`,
      runId: prConfig.runId || `dry-run-${fixtureName}`,
      generatedAt: prConfig.generatedAt || now,
      plan: plannerResult,
      guardrails: prConfig.guardrails || {},
    });
  } catch (error) {
    return {
      fixture: fixtureName,
      expectation: fixture?.expectation || "pass",
      status: "fail",
      failures: [{ stage: "pr_generation", message: `guardrail compile error: ${error.message}` }],
      stages: {
        planner: { status: plannerResult.changes.length > 0 ? "pass" : "fail", dryRun: plannerResult.dryRun, summary: plannerResult.summary },
        prGeneration: { status: "fail", gateStatus: "fail", pullRequestCount: 0, error: error.message },
        verification: { status: "blocked", decision: "required-block", verificationSummary: { reason: "pr_generation_failed" } },
      },
      outputs: {
        planner: plannerResult,
        prGeneration: { status: "blocked", gate: { status: "fail", reasonCodes: ["guardrail_compile_error"], reasons: [{ code: "guardrail_compile_error", severity: "error", message: error.message }] } },
        verification: { status: "blocked", decision: "required-block" },
      },
    };
  }

  const generatedPullRequests = Array.isArray(prResult?.pullRequests) ? prResult.pullRequests : [];
  const repositories = generatedPullRequests.map((pr) => String(pr?.repository || "unknown"));

  const verificationConfig = fixture?.verificationInput || {};
  const ciByRepository = buildCiByRepository(repositories, verificationConfig.failedChecks || []);

  const verificationResult = runVerificationHarness({
    now: verificationConfig.now || "2026-04-05T09:00:00.000Z",
    provider: verificationConfig.provider || "github_actions",
    prArtifacts: { pullRequests: generatedPullRequests },
    ciByRepository,
    policyArtifact: verificationConfig.policyArtifact || { attached: true, status: "pass" },
    baselineMetrics: verificationConfig.baselineMetrics || {
      truePositives: 188,
      falsePositives: 6,
      trueNegatives: 204,
      falseNegatives: 2,
    },
    reproducibleRuns: Number(verificationConfig.reproducibleRuns || 2),
    exceptions: Array.isArray(verificationConfig.exceptions) ? verificationConfig.exceptions : [],
  });

  const failures = [];
  const expected = fixture?.expected || {};

  assertStage(
    plannerResult.dryRun === Boolean(expected?.planner?.dryRun),
    "planner",
    `expected dryRun=${Boolean(expected?.planner?.dryRun)} but got ${plannerResult.dryRun}`,
    failures,
  );

  assertStage(
    plannerResult.changes.length >= Number(expected?.planner?.minChanges || 0),
    "planner",
    `expected at least ${Number(expected?.planner?.minChanges || 0)} changes but got ${plannerResult.changes.length}`,
    failures,
  );

  assertStage(
    prResult.status === String(expected?.prGeneration?.status || "ready"),
    "pr_generation",
    `expected status=${String(expected?.prGeneration?.status || "ready")} but got ${prResult.status}`,
    failures,
  );

  assertStage(
    generatedPullRequests.length >= Number(expected?.prGeneration?.minPullRequests || 0),
    "pr_generation",
    `expected at least ${Number(expected?.prGeneration?.minPullRequests || 0)} pull requests but got ${generatedPullRequests.length}`,
    failures,
  );

  assertStage(
    verificationResult.status === String(expected?.verification?.status || "ready"),
    "verification",
    `expected status=${String(expected?.verification?.status || "ready")} but got ${verificationResult.status}`,
    failures,
  );

  assertStage(
    verificationResult.decision === String(expected?.verification?.decision || "auto-merge"),
    "verification",
    `expected decision=${String(expected?.verification?.decision || "auto-merge")} but got ${verificationResult.decision}`,
    failures,
  );

  return {
    fixture: fixtureName,
    expectation: fixture?.expectation || "pass",
    status: failures.length === 0 ? "pass" : "fail",
    failures,
    stages: {
      planner: {
        status: plannerResult.changes.length > 0 ? "pass" : "fail",
        dryRun: plannerResult.dryRun,
        summary: plannerResult.summary,
      },
      prGeneration: {
        status: prResult.status === "ready" ? "pass" : "fail",
        gateStatus: prResult?.gate?.status || "unknown",
        pullRequestCount: generatedPullRequests.length,
      },
      verification: {
        status: verificationResult.status === "ready" ? "pass" : "fail",
        decision: verificationResult.decision,
        verificationSummary: verificationResult.verificationSummary,
      },
    },
    outputs: {
      planner: plannerResult,
      prGeneration: prResult,
      verification: verificationResult,
    },
  };
}

export function runRemediationDryRunHarness(input = {}) {
  const projectRoot = path.resolve(input.projectRoot || process.cwd());
  const now = input.now || "2026-04-05T09:00:00.000Z";
  const fixturesPath = path.resolve(
    projectRoot,
    input.fixturesPath || "fixtures/harness/remediation-dry-run/fixtures.json",
  );

  const fixtureEnvelope = readJson(fixturesPath);
  const fixtures = Array.isArray(fixtureEnvelope?.fixtures) ? fixtureEnvelope.fixtures : [];

  const results = fixtures.map((fixture) => runFixture(projectRoot, fixture, now));
  const failedFixtures = results.filter((result) => result.status !== "pass");

  return {
    generatedAt: now,
    fixtureCount: fixtures.length,
    passCount: results.length - failedFixtures.length,
    failCount: failedFixtures.length,
    status: failedFixtures.length === 0 ? "pass" : "fail",
    results,
  };
}
