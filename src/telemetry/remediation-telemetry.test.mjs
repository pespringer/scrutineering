import test from "node:test";
import assert from "node:assert/strict";
import { buildRemediationTelemetrySnapshot } from "./remediation-telemetry.mjs";

function createInput() {
  return {
    generatedAt: "2026-04-05T07:00:00.000Z",
    window: {
      start: "2026-03-29T00:00:00.000Z",
      end: "2026-04-05T00:00:00.000Z",
    },
    alertRouting: {
      owner: "platform-remediation-owner",
      onCall: "platform-security-oncall",
    },
    runs: [
      {
        id: "run-1",
        repository: "api",
        team: "payments",
        status: "success",
        startedAt: "2026-04-01T00:00:00.000Z",
        completedAt: "2026-04-01T00:20:00.000Z",
        vulnerabilitiesResolved: 4,
        vulnerabilitiesIntroduced: 0,
      },
      {
        id: "run-2",
        repository: "api",
        team: "payments",
        status: "failed_after_merge",
        startedAt: "2026-04-01T02:00:00.000Z",
        completedAt: "2026-04-01T03:30:00.000Z",
        vulnerabilitiesResolved: 1,
        vulnerabilitiesIntroduced: 2,
      },
      {
        id: "run-3",
        repository: "worker",
        team: "risk",
        status: "success",
        startedAt: "2026-04-02T01:00:00.000Z",
        completedAt: "2026-04-02T01:25:00.000Z",
        vulnerabilitiesResolved: 3,
        vulnerabilitiesIntroduced: 0,
      },
      {
        id: "run-4",
        repository: "worker",
        team: "risk",
        status: "failed",
        startedAt: "2026-04-03T01:00:00.000Z",
        completedAt: "2026-04-03T01:10:00.000Z",
        deployed: false,
        vulnerabilitiesResolved: 0,
        vulnerabilitiesIntroduced: 0,
      },
    ],
    vulnerabilityBacklog: [
      { scopeType: "team", scopeId: "payments", startingOpen: 25, endingOpen: 20 },
      { scopeType: "team", scopeId: "risk", startingOpen: 10, endingOpen: 8 },
      { scopeType: "repository", scopeId: "api", startingOpen: 20, endingOpen: 17 },
      { scopeType: "repository", scopeId: "worker", startingOpen: 15, endingOpen: 11 },
    ],
  };
}

test("builds health and impact metrics by team and repository", () => {
  const snapshot = buildRemediationTelemetrySnapshot(createInput());

  assert.equal(snapshot.summary.totalRuns, 4);
  assert.equal(snapshot.summary.successfulRuns, 2);
  assert.equal(snapshot.summary.successRate, 50);
  assert.equal(snapshot.summary.changeFailureRate, 33.33);
  assert.equal(snapshot.summary.burndownRate, 20);

  assert.equal(snapshot.byTeam.length, 2);
  assert.equal(snapshot.byTeam[0].team, "payments");
  assert.equal(snapshot.byRepository.length, 2);
  assert.equal(snapshot.byRepository[1].repository, "worker");
});

test("raises SLO alerts and routes to owner plus on-call when thresholds are violated", () => {
  const input = createInput();
  input.sloTargets = {
    successRateMin: 0.9,
    latencyP95MinutesMax: 45,
    changeFailureRateMax: 0.05,
    vulnerabilityBurndownRateMin: 0.3,
  };

  const snapshot = buildRemediationTelemetrySnapshot(input);

  assert.ok(snapshot.alerts.length >= 3);
  assert.ok(snapshot.alerts.every((alert) => alert.routing.owner === "platform-remediation-owner"));
  assert.ok(snapshot.alerts.every((alert) => alert.routing.onCall === "platform-security-oncall"));
  assert.ok(snapshot.slos.some((slo) => slo.name === "change_failure_rate" && slo.ok === false));
});

test("handles empty inputs with fail-closed SLO evaluation", () => {
  const snapshot = buildRemediationTelemetrySnapshot({ runs: [], vulnerabilityBacklog: [] });

  assert.equal(snapshot.summary.totalRuns, 0);
  assert.equal(snapshot.summary.successRate, null);
  assert.equal(snapshot.summary.changeFailureRate, null);
  assert.equal(snapshot.summary.burndownRate, null);
  assert.equal(snapshot.alerts.length, 4);
});
