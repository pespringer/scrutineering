import test from "node:test";
import assert from "node:assert/strict";
import { evaluateRolloutDecision } from "./staged-rollout.mjs";

test("blocks when global kill switch is enabled", () => {
  const result = evaluateRolloutDecision({
    teamId: "team-alpha",
    riskLevel: "low",
    observedRunsInLastHour: 3,
    rollout: {
      killSwitchEnabled: true,
      teamAllowlist: ["team-alpha"],
      maxRunsPerHour: 10,
    },
  });

  assert.equal(result.decision, "required-block");
  assert.equal(result.reasons[0].code, "kill_switch_enabled");
});

test("blocks when team is not in rollout allowlist", () => {
  const result = evaluateRolloutDecision({
    teamId: "team-beta",
    riskLevel: "low",
    observedRunsInLastHour: 1,
    rollout: {
      killSwitchEnabled: false,
      teamAllowlist: ["team-alpha"],
      maxRunsPerHour: 10,
    },
  });

  assert.equal(result.decision, "required-block");
  assert.equal(result.reasons[0].code, "team_not_allowlisted");
});

test("blocks when per-hour rate limit is exceeded", () => {
  const result = evaluateRolloutDecision({
    teamId: "team-alpha",
    riskLevel: "low",
    observedRunsInLastHour: 25,
    rollout: {
      killSwitchEnabled: false,
      teamAllowlist: ["team-alpha"],
      maxRunsPerHour: 25,
    },
  });

  assert.equal(result.decision, "required-block");
  assert.equal(result.reasons[0].code, "rate_limit_exceeded");
});

test("requires manual approval when risk threshold is met", () => {
  const result = evaluateRolloutDecision({
    teamId: "team-alpha",
    riskLevel: "high",
    observedRunsInLastHour: 5,
    rollout: {
      killSwitchEnabled: false,
      teamAllowlist: ["team-alpha"],
      maxRunsPerHour: 20,
      requireManualApprovalRiskAtOrAbove: "high",
    },
  });

  assert.equal(result.decision, "manual-approval");
  assert.equal(result.reasons[0].code, "risk_requires_manual_approval");
});

test("returns auto-merge when all controls pass", () => {
  const result = evaluateRolloutDecision({
    teamId: "team-alpha",
    riskLevel: "medium",
    observedRunsInLastHour: 4,
    rollout: {
      killSwitchEnabled: false,
      teamAllowlist: ["team-alpha", "team-gamma"],
      maxRunsPerHour: 20,
      requireManualApprovalRiskAtOrAbove: "high",
    },
  });

  assert.equal(result.decision, "auto-merge");
  assert.equal(result.status, "ready");
  assert.equal(result.reasons[0].code, "rollout_controls_passed");
});
