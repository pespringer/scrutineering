const supportedProviders = new Set(["github_actions", "circleci", "generic"]);

function normalizeProvider(provider) {
  const key = String(provider || "").trim().toLowerCase();
  return supportedProviders.has(key) ? key : "github_actions";
}

function normalizeStatus(status) {
  const key = String(status || "").trim().toLowerCase();
  if (key === "success" || key === "passed" || key === "pass") {
    return "success";
  }
  if (key === "pending" || key === "running" || key === "queued") {
    return "pending";
  }
  return "failed";
}

function mapEventToTrigger(eventName) {
  const key = String(eventName || "").trim().toLowerCase();
  if (key === "pull_request" || key === "pull_request_target") {
    return "pr_open_or_update";
  }
  if (key === "workflow_dispatch") {
    return "manual_dispatch";
  }
  if (key === "schedule") {
    return "scheduled_scan";
  }
  if (key === "push") {
    return "default_branch_push";
  }
  return "unsupported_event";
}

function normalizeChecks(checks = []) {
  return checks.map((check) => ({
    name: String(check?.name || "").trim(),
    status: normalizeStatus(check?.status),
    required: Boolean(check?.required),
  }));
}

function evaluateRequiredChecks(checks) {
  const requiredChecks = checks.filter((check) => check.required);

  const failed = requiredChecks.filter((check) => check.status === "failed");
  const pending = requiredChecks.filter((check) => check.status === "pending");

  if (failed.length > 0) {
    return {
      status: "fail",
      reasonCode: "required_check_failed",
      details: failed.map((check) => check.name),
    };
  }

  if (pending.length > 0) {
    return {
      status: "wait",
      reasonCode: "required_check_pending",
      details: pending.map((check) => check.name),
    };
  }

  return {
    status: "pass",
    reasonCode: "all_required_checks_passed",
    details: requiredChecks.map((check) => check.name),
  };
}

export function evaluateCiChecks(input = {}) {
  const provider = normalizeProvider(input.provider);
  const eventName = String(input.eventName || "").trim();
  const trigger = mapEventToTrigger(eventName);
  const checks = normalizeChecks(Array.isArray(input.checks) ? input.checks : []);

  if (checks.length === 0) {
    return {
      provider,
      eventName,
      trigger,
      decision: "required-block",
      status: "blocked",
      reasons: [
        {
          code: "missing_checks",
          message: "No CI checks provided for evaluation.",
        },
      ],
      summary: {
        totalChecks: 0,
        requiredChecks: 0,
      },
    };
  }

  const gate = evaluateRequiredChecks(checks);
  const unsupportedTrigger = trigger === "unsupported_event";

  if (gate.status === "fail") {
    return {
      provider,
      eventName,
      trigger,
      decision: "required-block",
      status: "blocked",
      reasons: [
        {
          code: gate.reasonCode,
          message: "At least one required CI check failed.",
          checks: gate.details,
        },
      ],
      summary: {
        totalChecks: checks.length,
        requiredChecks: checks.filter((check) => check.required).length,
      },
    };
  }

  if (gate.status === "wait") {
    return {
      provider,
      eventName,
      trigger,
      decision: "manual-approval",
      status: "pending",
      reasons: [
        {
          code: gate.reasonCode,
          message: "Required CI checks are still pending.",
          checks: gate.details,
        },
      ],
      summary: {
        totalChecks: checks.length,
        requiredChecks: checks.filter((check) => check.required).length,
      },
    };
  }

  if (unsupportedTrigger) {
    return {
      provider,
      eventName,
      trigger,
      decision: "manual-approval",
      status: "pending",
      reasons: [
        {
          code: "unsupported_repo_event",
          message: "Repo event is not in the remediation trigger allowlist.",
        },
      ],
      summary: {
        totalChecks: checks.length,
        requiredChecks: checks.filter((check) => check.required).length,
      },
    };
  }

  return {
    provider,
    eventName,
    trigger,
    decision: "auto-merge",
    status: "ready",
    reasons: [
      {
        code: gate.reasonCode,
        message: "All required CI checks passed for an allowed remediation trigger.",
      },
    ],
    summary: {
      totalChecks: checks.length,
      requiredChecks: checks.filter((check) => check.required).length,
    },
  };
}
