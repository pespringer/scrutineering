const DEFAULT_SLO_TARGETS = {
  successRateMin: 0.97,
  latencyP95MinutesMax: 60,
  changeFailureRateMax: 0.1,
  vulnerabilityBurndownRateMin: 0.2,
};

function asFiniteNumber(value, fallback = 0) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : fallback;
}

function divideSafe(numerator, denominator) {
  if (!Number.isFinite(numerator) || !Number.isFinite(denominator) || denominator <= 0) {
    return null;
  }
  return numerator / denominator;
}

function percentile(sortedNumbers, p) {
  if (!Array.isArray(sortedNumbers) || sortedNumbers.length === 0) {
    return null;
  }

  const idx = Math.max(0, Math.min(sortedNumbers.length - 1, Math.ceil(sortedNumbers.length * p) - 1));
  return sortedNumbers[idx];
}

function normalizeStatus(status) {
  const key = String(status || "").trim().toLowerCase();
  if (["success", "ready", "merged"].includes(key)) {
    return "success";
  }
  if (["failed_after_merge", "rollback", "regressed"].includes(key)) {
    return "failed_after_merge";
  }
  if (["failed", "blocked", "error"].includes(key)) {
    return "failed";
  }
  return "unknown";
}

function normalizeRun(raw, index) {
  const startedAt = new Date(raw?.startedAt || "");
  const completedAt = new Date(raw?.completedAt || "");
  const hasStart = !Number.isNaN(startedAt.getTime());
  const hasEnd = !Number.isNaN(completedAt.getTime());
  const durationMs = hasStart && hasEnd && completedAt >= startedAt ? completedAt - startedAt : null;
  const status = normalizeStatus(raw?.status);

  return {
    id: String(raw?.id || `run-${index + 1}`),
    repository: String(raw?.repository || "unknown"),
    team: String(raw?.team || "unknown"),
    status,
    startedAt: hasStart ? startedAt.toISOString() : null,
    completedAt: hasEnd ? completedAt.toISOString() : null,
    durationMs,
    deployed: raw?.deployed !== false,
    vulnerabilitiesResolved: Math.max(0, asFiniteNumber(raw?.vulnerabilitiesResolved, 0)),
    vulnerabilitiesIntroduced: Math.max(0, asFiniteNumber(raw?.vulnerabilitiesIntroduced, 0)),
  };
}

function computeScopeMetrics(runs) {
  const completedRuns = runs.filter((run) => run.durationMs !== null);
  const successfulRuns = runs.filter((run) => run.status === "success");
  const deploymentRuns = runs.filter((run) => run.deployed);
  const failedAfterMerge = runs.filter((run) => run.status === "failed_after_merge");

  const latencies = completedRuns
    .map((run) => run.durationMs)
    .filter((value) => Number.isFinite(value))
    .sort((a, b) => a - b);

  const latencyP50Minutes = divideSafe(percentile(latencies, 0.5), 60 * 1000);
  const latencyP95Minutes = divideSafe(percentile(latencies, 0.95), 60 * 1000);
  const successRate = divideSafe(successfulRuns.length, completedRuns.length);
  const changeFailureRate = divideSafe(failedAfterMerge.length, deploymentRuns.length);

  const vulnerabilitiesResolved = runs.reduce((sum, run) => sum + run.vulnerabilitiesResolved, 0);
  const vulnerabilitiesIntroduced = runs.reduce((sum, run) => sum + run.vulnerabilitiesIntroduced, 0);

  return {
    totalRuns: runs.length,
    completedRuns: completedRuns.length,
    successfulRuns: successfulRuns.length,
    failedRuns: runs.filter((run) => run.status === "failed").length,
    failedAfterMergeRuns: failedAfterMerge.length,
    successRate,
    changeFailureRate,
    latencyP50Minutes,
    latencyP95Minutes,
    vulnerabilitiesResolved,
    vulnerabilitiesIntroduced,
    netVulnerabilityDelta: vulnerabilitiesIntroduced - vulnerabilitiesResolved,
  };
}

function groupBy(rows, keyFn) {
  const groups = new Map();
  for (const row of rows) {
    const key = keyFn(row);
    const current = groups.get(key) || [];
    current.push(row);
    groups.set(key, current);
  }
  return groups;
}

function summarizeBurndown(rows) {
  const normalized = Array.isArray(rows)
    ? rows.map((row) => ({
        scopeType: String(row?.scopeType || "unknown"),
        scopeId: String(row?.scopeId || "unknown"),
        startingOpen: Math.max(0, asFiniteNumber(row?.startingOpen, 0)),
        endingOpen: Math.max(0, asFiniteNumber(row?.endingOpen, 0)),
      }))
    : [];

  return normalized.map((row) => {
    const resolved = Math.max(0, row.startingOpen - row.endingOpen);
    return {
      ...row,
      resolved,
      burndownRate: divideSafe(resolved, row.startingOpen),
    };
  });
}

function evaluateSlos(snapshot, input) {
  const targets = {
    ...DEFAULT_SLO_TARGETS,
    ...(input?.sloTargets || {}),
  };

  const slos = [
    {
      name: "success_rate",
      target: `>= ${Math.round(targets.successRateMin * 100)}%`,
      observed: snapshot.summary.successRate,
      ok: snapshot.summary.successRate !== null && snapshot.summary.successRate >= targets.successRateMin,
      alertCode: "slo_success_rate_breach",
      description: "Automated remediation success rate",
    },
    {
      name: "latency_p95",
      target: `<= ${targets.latencyP95MinutesMax}m`,
      observed: snapshot.summary.latencyP95Minutes,
      ok:
        snapshot.summary.latencyP95Minutes !== null &&
        snapshot.summary.latencyP95Minutes <= targets.latencyP95MinutesMax,
      alertCode: "slo_latency_p95_breach",
      description: "End-to-end remediation latency (P95)",
    },
    {
      name: "change_failure_rate",
      target: `<= ${Math.round(targets.changeFailureRateMax * 100)}%`,
      observed: snapshot.summary.changeFailureRate,
      ok:
        snapshot.summary.changeFailureRate !== null &&
        snapshot.summary.changeFailureRate <= targets.changeFailureRateMax,
      alertCode: "slo_change_failure_rate_breach",
      description: "Post-merge remediation regressions",
    },
    {
      name: "vulnerability_burndown",
      target: `>= ${Math.round(targets.vulnerabilityBurndownRateMin * 100)}%`,
      observed: snapshot.summary.burndownRate,
      ok:
        snapshot.summary.burndownRate !== null &&
        snapshot.summary.burndownRate >= targets.vulnerabilityBurndownRateMin,
      alertCode: "slo_vulnerability_burndown_breach",
      description: "Open vulnerability burn-down over the reporting window",
    },
  ];

  const routing = {
    owner: String(input?.alertRouting?.owner || "security-platform-owner"),
    onCall: String(input?.alertRouting?.onCall || "security-platform-oncall"),
  };

  const alerts = slos
    .filter((slo) => !slo.ok)
    .map((slo) => ({
      severity: "high",
      code: slo.alertCode,
      message: `${slo.description} is out of SLO.`,
      routing,
    }));

  return {
    slos,
    alerts,
  };
}

function toFixedPercent(value) {
  if (value === null || !Number.isFinite(value)) {
    return null;
  }
  return Number((value * 100).toFixed(2));
}

function toFixedMinutes(value) {
  if (value === null || !Number.isFinite(value)) {
    return null;
  }
  return Number(value.toFixed(2));
}

export function buildRemediationTelemetrySnapshot(input = {}) {
  const runs = (Array.isArray(input.runs) ? input.runs : []).map(normalizeRun);
  const window = {
    start: input?.window?.start || null,
    end: input?.window?.end || null,
  };

  const byTeam = Array.from(groupBy(runs, (run) => run.team).entries())
    .map(([team, teamRuns]) => ({
      team,
      ...computeScopeMetrics(teamRuns),
    }))
    .sort((a, b) => a.team.localeCompare(b.team, "en"));

  const byRepository = Array.from(groupBy(runs, (run) => run.repository).entries())
    .map(([repository, repoRuns]) => ({
      repository,
      ...computeScopeMetrics(repoRuns),
    }))
    .sort((a, b) => a.repository.localeCompare(b.repository, "en"));

  const summaryMetrics = computeScopeMetrics(runs);

  const burndown = summarizeBurndown(input.vulnerabilityBacklog);
  const totalStartingOpen = burndown.reduce((sum, row) => sum + row.startingOpen, 0);
  const totalEndingOpen = burndown.reduce((sum, row) => sum + row.endingOpen, 0);
  const totalResolved = Math.max(0, totalStartingOpen - totalEndingOpen);
  const burndownRate = divideSafe(totalResolved, totalStartingOpen);

  const snapshot = {
    generatedAt: input.generatedAt || new Date().toISOString(),
    window,
    summary: {
      ...summaryMetrics,
      burndown: {
        startingOpen: totalStartingOpen,
        endingOpen: totalEndingOpen,
        resolved: totalResolved,
      },
      burndownRate,
    },
    byTeam,
    byRepository,
    vulnerabilityBacklog: burndown,
  };

  const sloEvaluation = evaluateSlos(snapshot, input);

  const withFormattedNumbers = {
    ...snapshot,
    summary: {
      ...snapshot.summary,
      successRate: toFixedPercent(snapshot.summary.successRate),
      changeFailureRate: toFixedPercent(snapshot.summary.changeFailureRate),
      latencyP50Minutes: toFixedMinutes(snapshot.summary.latencyP50Minutes),
      latencyP95Minutes: toFixedMinutes(snapshot.summary.latencyP95Minutes),
      burndownRate: toFixedPercent(snapshot.summary.burndownRate),
    },
    byTeam: snapshot.byTeam.map((row) => ({
      ...row,
      successRate: toFixedPercent(row.successRate),
      changeFailureRate: toFixedPercent(row.changeFailureRate),
      latencyP50Minutes: toFixedMinutes(row.latencyP50Minutes),
      latencyP95Minutes: toFixedMinutes(row.latencyP95Minutes),
    })),
    byRepository: snapshot.byRepository.map((row) => ({
      ...row,
      successRate: toFixedPercent(row.successRate),
      changeFailureRate: toFixedPercent(row.changeFailureRate),
      latencyP50Minutes: toFixedMinutes(row.latencyP50Minutes),
      latencyP95Minutes: toFixedMinutes(row.latencyP95Minutes),
    })),
    slos: sloEvaluation.slos.map((slo) => ({
      ...slo,
      observed:
        slo.name === "latency_p95"
          ? toFixedMinutes(slo.observed)
          : toFixedPercent(slo.observed),
    })),
    alerts: sloEvaluation.alerts,
  };

  return withFormattedNumbers;
}
