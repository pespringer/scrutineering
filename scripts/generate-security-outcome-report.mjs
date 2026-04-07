import fs from "node:fs";
import path from "node:path";
import { buildRemediationTelemetrySnapshot } from "../src/telemetry/remediation-telemetry.mjs";

const projectRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const inputPath = path.join(projectRoot, "fixtures", "telemetry", "weekly-remediation-sample.json");
const outputPath = path.join(projectRoot, "docs", "operations", "weekly-security-outcome-report.md");

const seeded = JSON.parse(fs.readFileSync(inputPath, "utf8"));
const snapshot = buildRemediationTelemetrySnapshot(seeded);

function asPercent(value) {
  return value === null ? "n/a" : `${value.toFixed(2)}%`;
}

function asMinutes(value) {
  return value === null ? "n/a" : `${value.toFixed(2)}m`;
}

const lines = [];
lines.push("# Weekly Security Outcome Report");
lines.push("");
lines.push(`Generated at: ${snapshot.generatedAt}`);
lines.push(`Window: ${snapshot.window.start || "n/a"} -> ${snapshot.window.end || "n/a"}`);
lines.push("");
lines.push("## Executive Summary");
lines.push("");
lines.push(`- Total remediation runs: ${snapshot.summary.totalRuns}`);
lines.push(`- Success rate: ${asPercent(snapshot.summary.successRate)}`);
lines.push(`- P95 latency: ${asMinutes(snapshot.summary.latencyP95Minutes)}`);
lines.push(`- Change-failure rate: ${asPercent(snapshot.summary.changeFailureRate)}`);
lines.push(`- Vulnerability burn-down: ${asPercent(snapshot.summary.burndownRate)} (${snapshot.summary.burndown.resolved} resolved)`);
lines.push(`- SLO alerts this window: ${snapshot.alerts.length}`);
lines.push("");
lines.push("## Dashboard View by Team");
lines.push("");
lines.push("| Team | Runs | Success Rate | P95 Latency | Change Failure Rate | Net Vulnerability Delta |",);
lines.push("|---|---:|---:|---:|---:|---:|");
for (const row of snapshot.byTeam) {
  lines.push(
    `| ${row.team} | ${row.totalRuns} | ${asPercent(row.successRate)} | ${asMinutes(row.latencyP95Minutes)} | ${asPercent(row.changeFailureRate)} | ${row.netVulnerabilityDelta} |`,
  );
}
lines.push("");
lines.push("## Dashboard View by Repository");
lines.push("");
lines.push("| Repository | Runs | Success Rate | P95 Latency | Change Failure Rate | Net Vulnerability Delta |",);
lines.push("|---|---:|---:|---:|---:|---:|");
for (const row of snapshot.byRepository) {
  lines.push(
    `| ${row.repository} | ${row.totalRuns} | ${asPercent(row.successRate)} | ${asMinutes(row.latencyP95Minutes)} | ${asPercent(row.changeFailureRate)} | ${row.netVulnerabilityDelta} |`,
  );
}
lines.push("");
lines.push("## SLO Status");
lines.push("");
lines.push("| SLO | Target | Observed | Status |",);
lines.push("|---|---|---|---|");
for (const slo of snapshot.slos) {
  const observed = slo.name === "latency_p95" ? asMinutes(slo.observed) : asPercent(slo.observed);
  lines.push(`| ${slo.name} | ${slo.target} | ${observed} | ${slo.ok ? "pass" : "breach"} |`);
}
lines.push("");
lines.push("## Alert Routing");
lines.push("");
if (snapshot.alerts.length === 0) {
  lines.push("- No SLO breaches this week.");
} else {
  for (const alert of snapshot.alerts) {
    lines.push(`- ${alert.code}: ${alert.message} -> owner=${alert.routing.owner}, on-call=${alert.routing.onCall}`);
  }
}

fs.writeFileSync(outputPath, `${lines.join("\n")}\n`, "utf8");
console.log(`Wrote ${outputPath}`);
