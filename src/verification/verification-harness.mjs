import { evaluateCiChecks } from "../ci/ci-integration.mjs";

const REQUIRED_SECURITY_CHECKS = [
  "dependency_scan",
  "container_image_scan",
  "static_analysis",
  "secrets_detection",
  "verification_harness_health",
  "regression_scope",
];

const DAY_MS = 24 * 60 * 60 * 1000;

function asNumber(value, fallback = 0) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : fallback;
}

function divideSafe(numerator, denominator) {
  if (!Number.isFinite(numerator) || !Number.isFinite(denominator) || denominator <= 0) {
    return null;
  }
  return numerator / denominator;
}

function summarizeBaseline(metrics = {}) {
  const truePositives = asNumber(metrics.truePositives, 0);
  const falsePositives = asNumber(metrics.falsePositives, 0);
  const trueNegatives = asNumber(metrics.trueNegatives, 0);
  const falseNegatives = asNumber(metrics.falseNegatives, 0);

  const total = truePositives + falsePositives + trueNegatives + falseNegatives;

  return {
    confusionMatrix: {
      truePositives,
      falsePositives,
      trueNegatives,
      falseNegatives,
    },
    sampleSize: total,
    precision: divideSafe(truePositives, truePositives + falsePositives),
    recall: divideSafe(truePositives, truePositives + falseNegatives),
    falsePositiveRate: divideSafe(falsePositives, falsePositives + trueNegatives),
    falseNegativeRate: divideSafe(falseNegatives, falseNegatives + truePositives),
  };
}

function evaluateExceptionPolicy(exceptions, nowIso) {
  const now = new Date(nowIso);
  const reasons = [];

  for (const exception of exceptions) {
    const severity = String(exception?.severity || "").toLowerCase();
    const approvedBy = String(exception?.approvedBy || "").toLowerCase();
    const hasCompleteEvidence = Boolean(exception?.hasCompleteEvidence);
    const owner = String(exception?.owner || "").trim();
    const findingId = String(exception?.findingId || "").trim();
    const expiresAt = new Date(exception?.expiresAt || "");
    const active = !Number.isNaN(expiresAt.getTime()) && expiresAt > now;
    const durationDays = active ? (expiresAt.getTime() - now.getTime()) / DAY_MS : null;

    if (!active) {
      reasons.push({
        code: "exception_expired",
        message: `Exception ${exception?.id || "<unknown>"} has expired or is invalid.`,
      });
    }

    if (durationDays !== null && durationDays > 14) {
      reasons.push({
        code: "exception_window_exceeded",
        message: `Exception ${exception?.id || "<unknown>"} exceeds 14-day expiration limit.`,
      });
    }

    if (!["cto", "security_owner"].includes(approvedBy)) {
      reasons.push({
        code: "exception_invalid_approver",
        message: `Exception ${exception?.id || "<unknown>"} approver is not allowed.`,
      });
    }

    if (!hasCompleteEvidence || !owner || !findingId) {
      reasons.push({
        code: "exception_missing_evidence",
        message: `Exception ${exception?.id || "<unknown>"} is missing required evidence fields.`,
      });
    }

    if (severity === "critical" && Boolean(exception?.confirmedExploitable)) {
      reasons.push({
        code: "exception_critical_exploitable_denied",
        message: `Exception ${exception?.id || "<unknown>"} cannot waive exploitable critical findings.`,
      });
    }
  }

  return {
    status: reasons.length === 0 ? "pass" : "fail",
    reasonCodes: reasons.map((reason) => reason.code),
    reasons,
    totalExceptions: exceptions.length,
  };
}

function evaluateReproducibility(reproducibleRuns) {
  const runCount = asNumber(reproducibleRuns, 0);
  if (runCount >= 2) {
    return {
      status: "pass",
      reasonCodes: [],
      reasons: [],
      runCount,
    };
  }

  return {
    status: "fail",
    reasonCodes: ["insufficient_reproducible_runs"],
    reasons: [
      {
        code: "insufficient_reproducible_runs",
        message: "Verification harness must reproduce results for at least two consecutive runs on the same SHA.",
      },
    ],
    runCount,
  };
}

function evaluatePolicyArtifact(policy = {}) {
  if (!policy?.attached) {
    return {
      status: "fail",
      reasonCodes: ["missing_policy_result_artifact"],
      reasons: [
        {
          code: "missing_policy_result_artifact",
          message: "Policy result artifact is not attached to the verification run.",
        },
      ],
    };
  }

  if (String(policy.status || "pass").toLowerCase() !== "pass") {
    return {
      status: "fail",
      reasonCodes: ["policy_result_failed"],
      reasons: [
        {
          code: "policy_result_failed",
          message: "Policy result artifact indicates a failed verification policy gate.",
        },
      ],
    };
  }

  return {
    status: "pass",
    reasonCodes: [],
    reasons: [],
  };
}

function buildCheckSet(inputChecks = []) {
  const checks = Array.isArray(inputChecks) ? [...inputChecks] : [];
  const seen = new Set(checks.map((check) => String(check?.name || "").trim()));

  for (const name of REQUIRED_SECURITY_CHECKS) {
    if (!seen.has(name)) {
      checks.push({
        name,
        status: "pending",
        required: true,
      });
    }
  }

  return checks;
}

function asGate(name, result, metadata = {}) {
  return {
    name,
    status: result.status,
    reasonCodes: Array.isArray(result.reasonCodes) ? result.reasonCodes : [],
    reasons: Array.isArray(result.reasons) ? result.reasons : [],
    metadata,
  };
}

function aggregateStatus(gates = []) {
  if (gates.some((gate) => gate.status === "fail")) {
    return {
      decision: "required-block",
      status: "blocked",
    };
  }

  if (gates.some((gate) => gate.status === "wait")) {
    return {
      decision: "manual-approval",
      status: "pending",
    };
  }

  return {
    decision: "auto-merge",
    status: "ready",
  };
}

export function runVerificationHarness(input = {}) {
  const now = input.now || new Date().toISOString();
  const prArtifacts = input.prArtifacts || {};
  const pullRequests = Array.isArray(prArtifacts.pullRequests) ? prArtifacts.pullRequests : [];
  const ciByRepository = input.ciByRepository || {};
  const baseline = summarizeBaseline(input.baselineMetrics || {});
  const exceptions = Array.isArray(input.exceptions) ? input.exceptions : [];

  const policyGate = evaluatePolicyArtifact(input.policyArtifact || {});
  const exceptionGate = evaluateExceptionPolicy(exceptions, now);
  const reproducibilityGate = evaluateReproducibility(input.reproducibleRuns);

  const verificationPerPullRequest = pullRequests.map((pullRequest) => {
    const repository = String(pullRequest?.repository || "unknown");
    const checks = buildCheckSet(ciByRepository[repository]);
    const ciDecision = evaluateCiChecks({
      provider: input.provider || "github_actions",
      eventName: "pull_request",
      checks,
    });

    const gate = asGate(
      "ci_required_checks",
      {
        status:
          ciDecision.status === "ready" ? "pass" : ciDecision.status === "pending" ? "wait" : "fail",
        reasonCodes: ciDecision.reasons.map((reason) => reason.code),
        reasons: ciDecision.reasons,
      },
      {
        repository,
        requiredChecks: checks.filter((check) => check.required).map((check) => check.name),
      },
    );

    const artifact = {
      repository,
      branch: pullRequest.branch,
      fingerprint: pullRequest.fingerprint,
      decision: ciDecision.decision,
      status: ciDecision.status,
      reasons: ciDecision.reasons,
      summary: ciDecision.summary,
      generatedAt: now,
      gate,
    };

    return {
      repository,
      branch: pullRequest.branch,
      fingerprint: pullRequest.fingerprint,
      verificationArtifact: artifact,
    };
  });

  const ciGates = verificationPerPullRequest.map((item) => item.verificationArtifact.gate);

  const harnessGates = [
    asGate("policy_artifact", policyGate),
    asGate("exception_policy", exceptionGate, { totalExceptions: exceptions.length }),
    asGate("reproducibility", reproducibilityGate, { reproducibleRuns: reproducibilityGate.runCount }),
    ...ciGates,
  ];

  const aggregate = aggregateStatus(harnessGates);

  return {
    status: aggregate.status,
    decision: aggregate.decision,
    generatedAt: now,
    verificationSummary: {
      pullRequestCount: pullRequests.length,
      requiredCheckNames: REQUIRED_SECURITY_CHECKS,
      policyGateStatus: policyGate.status,
      exceptionGateStatus: exceptionGate.status,
      reproducibilityStatus: reproducibilityGate.status,
    },
    gates: harnessGates,
    baselineMetrics: baseline,
    pullRequests: verificationPerPullRequest,
  };
}
