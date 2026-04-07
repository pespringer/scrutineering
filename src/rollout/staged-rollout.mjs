const riskRank = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

function normalizeRiskLevel(riskLevel) {
  const key = String(riskLevel || "").trim().toLowerCase();
  return riskRank[key] ? key : "medium";
}

function asPositiveInteger(value, fallback) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric < 0) {
    return fallback;
  }
  return Math.floor(numeric);
}

function normalizeRolloutConfig(config = {}) {
  return {
    teamAllowlist: Array.isArray(config.teamAllowlist) ? config.teamAllowlist.map(String) : [],
    killSwitchEnabled: Boolean(config.killSwitchEnabled),
    maxRunsPerHour: asPositiveInteger(config.maxRunsPerHour, 25),
    requireManualApprovalRiskAtOrAbove: normalizeRiskLevel(
      config.requireManualApprovalRiskAtOrAbove || "high",
    ),
  };
}

export function evaluateRolloutDecision(input = {}) {
  const teamId = String(input.teamId || "").trim();
  const riskLevel = normalizeRiskLevel(input.riskLevel);
  const config = normalizeRolloutConfig(input.rollout);
  const observedRunsInLastHour = asPositiveInteger(input.observedRunsInLastHour, 0);

  if (config.killSwitchEnabled) {
    return {
      decision: "required-block",
      status: "blocked",
      reasons: [
        {
          code: "kill_switch_enabled",
          message: "Global kill switch is enabled.",
        },
      ],
      controls: {
        killSwitchEnabled: true,
        teamAllowed: false,
        rateLimit: {
          maxRunsPerHour: config.maxRunsPerHour,
          observedRunsInLastHour,
          limited: true,
        },
      },
    };
  }

  const teamAllowed = config.teamAllowlist.length === 0 || config.teamAllowlist.includes(teamId);
  if (!teamAllowed) {
    return {
      decision: "required-block",
      status: "blocked",
      reasons: [
        {
          code: "team_not_allowlisted",
          message: `Team ${teamId || "<unknown>"} is not enabled for rollout.`,
        },
      ],
      controls: {
        killSwitchEnabled: false,
        teamAllowed: false,
        rateLimit: {
          maxRunsPerHour: config.maxRunsPerHour,
          observedRunsInLastHour,
          limited: false,
        },
      },
    };
  }

  if (observedRunsInLastHour >= config.maxRunsPerHour) {
    return {
      decision: "required-block",
      status: "blocked",
      reasons: [
        {
          code: "rate_limit_exceeded",
          message: "Rollout rate limit reached for the current hour.",
          details: {
            observedRunsInLastHour,
            maxRunsPerHour: config.maxRunsPerHour,
          },
        },
      ],
      controls: {
        killSwitchEnabled: false,
        teamAllowed: true,
        rateLimit: {
          maxRunsPerHour: config.maxRunsPerHour,
          observedRunsInLastHour,
          limited: true,
        },
      },
    };
  }

  const manualRiskThreshold = config.requireManualApprovalRiskAtOrAbove;
  if (riskRank[riskLevel] >= riskRank[manualRiskThreshold]) {
    return {
      decision: "manual-approval",
      status: "pending",
      reasons: [
        {
          code: "risk_requires_manual_approval",
          message: `Risk level ${riskLevel} requires manual approval at threshold ${manualRiskThreshold}.`,
        },
      ],
      controls: {
        killSwitchEnabled: false,
        teamAllowed: true,
        rateLimit: {
          maxRunsPerHour: config.maxRunsPerHour,
          observedRunsInLastHour,
          limited: false,
        },
      },
    };
  }

  return {
    decision: "auto-merge",
    status: "ready",
    reasons: [
      {
        code: "rollout_controls_passed",
        message: "Team rollout, kill switch, and rate-limit controls passed.",
      },
    ],
    controls: {
      killSwitchEnabled: false,
      teamAllowed: true,
      rateLimit: {
        maxRunsPerHour: config.maxRunsPerHour,
        observedRunsInLastHour,
        limited: false,
      },
    },
  };
}
