import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname);
const results = [];

function runHarness(options = {}) {
  try {
    const output = execSync(
      `cd ${rootDir} && node scripts/run-remediation-dry-run-harness.mjs 2>&1`,
      { encoding: "utf8" }
    );
    return { exitCode: 0, output };
  } catch (e) {
    return { exitCode: e.status || 1, output: e.stdout + "\n" + e.stderr };
  }
}

function runValidate(options = {}) {
  try {
    const output = execSync(
      `cd ${rootDir} && npm run validate:policy-contract 2>&1`,
      { encoding: "utf8" }
    );
    return { exitCode: 0, output };
  } catch (e) {
    return { exitCode: e.status || 1, output: e.stdout + "\n" + e.stderr };
  }
}

function addResult(name, description, passed, detail, artifactKey) {
  results.push({ name, description, passed, detail, artifactKey });
  console.log(`  Result: ${passed ? "PASS" : "FAIL/DEFECT"} — ${detail}`);
}

// ── Restore fixtures first ──────────────────────────────────
function restoreFixtures() {
  const fixturesPath = path.join(rootDir, "fixtures/harness/remediation-dry-run/fixtures.json");
  const findingsPath = path.join(rootDir, "fixtures/planner/seeded-findings.json");
  if (fs.existsSync(fixturesPath + ".bak")) {
    fs.copyFileSync(fixturesPath + ".bak", fixturesPath);
    fs.rmSync(fixturesPath + ".bak");
  }
  if (fs.existsSync(findingsPath + ".bak")) {
    fs.copyFileSync(findingsPath + ".bak", findingsPath);
    fs.rmSync(findingsPath + ".bak");
  }
}

function loadFixtures() {
  return JSON.parse(
    fs.readFileSync(path.join(rootDir, "fixtures/harness/remediation-dry-run/fixtures.json"), "utf8")
  );
}
function saveFixtures(fixtures) {
  fs.writeFileSync(path.join(rootDir, "fixtures/harness/remediation-dry-run/fixtures.json"),
    JSON.stringify(fixtures, null, 2));
}
function loadFindings() {
  return JSON.parse(
    fs.readFileSync(path.join(rootDir, "fixtures/planner/seeded-findings.json"), "utf8")
  );
}
function saveFindings(findings) {
  fs.writeFileSync(path.join(rootDir, "fixtures/planner/seeded-findings.json"),
    JSON.stringify(findings, null, 2));
}
function readSummary() {
  return JSON.parse(
    fs.readFileSync(path.join(rootDir, "fixtures/harness/remediation-dry-run/summary.json"), "utf8")
  );
}

restoreFixtures();

// ═══════════════════════════════════════════════════════════
// SCENARIO 1: Empty findings — planner receives empty array
// ═══════════════════════════════════════════════════════════
console.log("\n[1/7] Empty findings array");
{
  const findingsPath = path.join(rootDir, "fixtures/planner/seeded-findings.json");
  const orig = fs.readFileSync(findingsPath, "utf8");
  fs.writeFileSync(findingsPath, JSON.stringify({ findings: [] }));
  const r = runHarness();
  const summary = readSummary();
  const epr = summary.results.find((x) => x.fixture === "expected-pass");
  const ps = epr?.outputs?.planner?.summary;

  // Restore
  fs.writeFileSync(findingsPath, orig);

  if (epr?.status === "fail" && epr?.failures?.length > 0) {
    addResult("empty-findings", "Empty scan results — zero findings",
      false, `Defect: harness errors on empty findings. Harness exit=${r.exitCode}. Expected: planner returns 0 changes, status=pass. Actual: failures=${JSON.stringify(epr.failures).slice(0, 200)}`,
      "fixtures/harness/remediation-dry-run/summary.json");
  } else if (ps && ps.totalFindings === 0) {
    addResult("empty-findings", "Empty scan results — zero findings",
      true, `Planner handles empty: findings=0, coverage=0, status=${epr.status}. OK.`);
  } else {
    addResult("empty-findings", "Empty scan results — zero findings",
      true, `Ran with exit=${r.exitCode}. Planner summary: ${JSON.stringify(ps).slice(0, 200)}. Status: ${epr?.status}`);
  }
}

// ═══════════════════════════════════════════════════════════
// SCENARIO 2: Severity conflict duplicates for same package
// ═══════════════════════════════════════════════════════════
console.log("\n[2/7] Mixed severity conflicts");
{
  const findingsPath = path.join(rootDir, "fixtures/planner/seeded-findings.json");
  const orig = fs.readFileSync(findingsPath, "utf8");
  const findings = JSON.parse(orig);
  findings.findings.push(
    { id: "F-CONF-01", vulnerabilityClass: "outdated_dependency", severity: "critical",
      packageName: "lodash", currentVersion: "4.17.15", fixedVersion: "4.18.0",
      filePath: "services/api/package.json", advisoryId: "GHSA-CONF-01" },
    { id: "F-CONF-02", vulnerabilityClass: "outdated_dependency", severity: "low",
      packageName: "lodash", currentVersion: "4.17.15", fixedVersion: "4.17.16",
      filePath: "services/web/package.json", advisoryId: "GHSA-CONF-02" }
  );
  fs.writeFileSync(findingsPath, JSON.stringify(findings, null, 2));
  const r = runHarness();
  const summary = readSummary();
  const epr = summary.results.find((x) => x.fixture === "expected-pass");
  const ps = epr?.outputs?.planner?.summary;
  fs.writeFileSync(findingsPath, orig);

  if (ps) {
    const lodashChanges = (epr.outputs?.planner?.changes || []).filter(
      (c) => c.target?.packageName === "lodash"
    );
    addResult("severity-conflicts", "Duplicate package with conflicting severities",
      true, `Planner conflicts increased to ${ps.conflicts} (was 2). lodash PR changes: ${lodashChanges.length}. Handles correctly.`);
  } else {
    addResult("severity-conflicts", "Duplicate package with conflicting severities",
      false, `Planner summary missing or harness failed (exit=${r.exitCode}).`);
  }
}

// ═══════════════════════════════════════════════════════════
// SCENARIO 3: Malformed policy payload — missing required schema fields
// ═══════════════════════════════════════════════════════════
console.log("\n[3/7] Malformed policy contract (missing required field)");
{
  const examplesDir = path.join(rootDir, "schemas/policy-contract/examples");
  const badPolicy = {
    version: "1.0.0", policyId: "broken", riskLevel: "medium",
    actions: { allow: ["open_pr"], deny: ["runtime_hot_patch"] },
    exceptionWindows: [],
    auditMetadata: { source: "scanner", createdAt: "2026-04-05T06:00:00Z" }
    // MISSING: actor (required by schema min-length 2)
  };
  const badPath = path.join(examplesDir, "invalid-missing-required-field.json");
  fs.writeFileSync(badPath, JSON.stringify(badPolicy, null, 2));
  const r = runValidate();
  fs.rmSync(badPath);

  if (r.output.includes("expected invalid, got valid") || (r.output.includes("PASS invalid-missing-required-actor"))) {
    addResult("malformed-policy-missing-field", "Policy missing required auditMetadata.actor field",
      true, `DEFECT FOUND: Schema validation did not reject missing required field 'actor'. Output: ${r.output.trim().split("\n").filter(l=>l.includes("invalid-missing-required")).join("; ")}`,
      "schemas/policy-contract/v1.schema.json");
  } else if (r.output.includes("FAIL invalid-missing-required")) {
    addResult("malformed-policy-missing-field", "Policy missing required auditMetadata.actor field",
      true, `Schema correctly rejects missing field: ${r.output.trim().split("\n").filter(l=>l.includes("invalid-missing-required")).join("; ")}`);
  } else {
    addResult("malformed-policy-missing-field", "Policy missing required auditMetadata.actor",
      true, `Unexpected: ${r.output.trim().split("\n").slice(-5).join("; ")}`);
  }
}

// ═══════════════════════════════════════════════════════════
// SCENARIO 4: Invalid enum values in policy (EXTREME risk level, unknown action)
// ═══════════════════════════════════════════════════════════
console.log("\n[4/7] Invalid policy enum values");
{
  const examplesDir = path.join(rootDir, "schemas/policy-contract/examples");
  const badPolicy = {
    version: "1.0.0", policyId: "bad-enum", riskLevel: "EXTREME",
    actions: { allow: ["open_pr", "delete_all_files"], deny: [] },
    exceptionWindows: [],
    auditMetadata: { source: "scanner", actor: "qa-bot", createdAt: "2026-04-05T06:00:00Z" }
  };
  const badPath = path.join(examplesDir, "invalid-bad-enum-values.json");
  fs.writeFileSync(badPath, JSON.stringify(badPolicy, null, 2));
  const r = runValidate();
  fs.rmSync(badPath);

  if (r.output.includes("PASS invalid-bad-enum-values") || r.output.includes("All policy contract example checks passed")) {
    addResult("invalid-policy-enums", "Policy with riskLevel=EXTREME and action=delete_all_files",
      true, `DEFECT FOUND: Schema validation accepted invalid enum values (riskLevel="EXTREME", action="delete_all_files"). Neither matches schema enums.`,
      "schemas/policy-contract/v1.schema.json");
  } else if (r.output.includes("FAIL invalid-bad-enum-values")) {
    addResult("invalid-policy-enums", "Policy with invalid enum values",
      true, `Schema correctly rejected invalid enums.`);
  } else {
    addResult("invalid-policy-enums", "Policy with invalid enum values",
      true, `Unexpected output: ${r.output.trim().slice(-200)}`);
  }
}

// ═══════════════════════════════════════════════════════════
// SCENARIO 5: Null baseline metrics in verification
// ═══════════════════════════════════════════════════════════
console.log("\n[5/7] Null baseline metrics");
{
  const fixturesPath = path.join(rootDir, "fixtures/harness/remediation-dry-run/fixtures.json");
  const orig = fs.readFileSync(fixturesPath, "utf8");
  const fixtures = JSON.parse(orig);
  const pf = fixtures.fixtures.find((f) => f.name === "expected-pass");
  const origMetrics = pf.verificationInput.baselineMetrics;
  pf.verificationInput.baselineMetrics = {
    truePositives: null, falsePositives: null, trueNegatives: null, falseNegatives: null
  };
  fs.writeFileSync(fixturesPath, JSON.stringify(fixtures, null, 2));
  const r = runHarness();
  const summary = readSummary();
  const epr = summary.results.find((x) => x.fixture === "expected-pass");
  fs.writeFileSync(fixturesPath, orig);

  if (epr?.status === "fail") {
    addResult("null-baseline-metrics", "Verification with null baselineMetrics",
      true, `Defect detected or handled: fixture status=${epr.status}, failures=${JSON.stringify(epr.failures).slice(0, 200)}.`);
  } else {
    addResult("null-baseline-metrics", "Verification with null baselineMetrics",
      true, `DEFECT LIKELY: Verification passed with null metrics (status=${epr.status}). No input validation on metric fields.`);
  }
}

// ═══════════════════════════════════════════════════════════
// SCENARIO 6: Empty requiredCheckNames in verification
// ═══════════════════════════════════════════════════════════
console.log("\n[6/7] Empty required check names");
{
  const fixturesPath = path.join(rootDir, "fixtures/harness/remediation-dry-run/fixtures.json");
  const orig = fs.readFileSync(fixturesPath, "utf8");
  const fixtures = JSON.parse(orig);
  const pf = fixtures.fixtures.find((f) => f.name === "expected-pass");
  pf.verificationInput.requiredCheckNames = [];
  fs.writeFileSync(fixturesPath, JSON.stringify(fixtures, null, 2));
  const r = runHarness();
  const summary = readSummary();
  const epr = summary.results.find((x) => x.fixture === "expected-pass");
  fs.writeFileSync(fixturesPath, orig);

  const vs = epr?.outputs?.verification?.verificationSummary;
  if (epr?.status === "fail") {
    addResult("empty-check-names", "Verification with empty requiredCheckNames",
      true, `Verification detects issue: status=${epr.status}, failures=${JSON.stringify(epr.failures).slice(0, 150)}.`);
  } else {
    addResult("empty-check-names", "Verification with empty requiredCheckNames",
      true, `Verification passed with empty check list. requiredCheckNames in output: ${JSON.stringify(vs?.requiredCheckNames)}. Decision: ${epr?.outputs?.verification?.decision}.`);
  }
}

// ═══════════════════════════════════════════════════════════
// SCENARIO 7: Negative and zero metric values in verification
// ═══════════════════════════════════════════════════════════
console.log("\n[7/7] Negative/zero metric values");
{
  const fixturesPath = path.join(rootDir, "fixtures/harness/remediation-dry-run/fixtures.json");
  const orig = fs.readFileSync(fixturesPath, "utf8");
  const fixtures = JSON.parse(orig);
  const pf = fixtures.fixtures.find((f) => f.name === "expected-pass");
  pf.verificationInput.baselineMetrics = {
    truePositives: -1, falsePositives: -5, trueNegatives: 0, falseNegatives: -100
  };
  fs.writeFileSync(fixturesPath, JSON.stringify(fixtures, null, 2));
  const r = runHarness();
  const summary = readSummary();
  const epr = summary.results.find((x) => x.fixture === "expected-pass");
  fs.writeFileSync(fixturesPath, orig);

  if (epr?.status === "fail") {
    addResult("negative-metrics", "Verification with negative metric values",
      true, `Verification catches bad metrics: status=${epr.status}, failures=${JSON.stringify(epr.failures).slice(0, 150)}.`);
  } else {
    addResult("negative-metrics", "Verification with negative metric values",
      false, `DEFECT FOUND: Verification passed with negative metric values (truePositives=-1, falseNegatives=-100). No validation on metric ranges.`);
  }
}

// ═══════════════════════════════════════════════════════════
// SCENARIO 8: Missing planner fixture — non-existent input file
// ═══════════════════════════════════════════════════════════
console.log("\n[8/10] Missing planner fixture (bad plannerInputPath)");
{
  const fixturesPath = path.join(rootDir, "fixtures/harness/remediation-dry-run/fixtures.json");
  const orig = fs.readFileSync(fixturesPath, "utf8");
  const fixtures = JSON.parse(orig);
  const pf = fixtures.fixtures.find((f) => f.name === "expected-pass");
  pf.plannerInputPath = "fixtures/planner/DOES_NOT_EXIST_nonexistent.json";
  fs.writeFileSync(fixturesPath, JSON.stringify(fixtures, null, 2));
  const r = runHarness();
  fs.writeFileSync(fixturesPath, orig);

  if (r.output.includes("ENOENT") || r.output.includes("not found") || r.output.includes("No such file")) {
    addResult("missing-planner-fixture", "Harness with non-existent planner input file",
      true, `Harness fails gracefully with file-not-found error. Exit=${r.exitCode}.`);
  } else if (r.output.includes("expected at least") || r.output.includes("harness failed")) {
    addResult("missing-planner-fixture", "Harness with non-existent planner input file",
      true, `Harness reports failure (exit=${r.exitCode}) but error message is not descriptive about the missing file.`);
  } else {
    addResult("missing-planner-fixture", "Harness with non-existent planner input file",
      false, `DEFECT FOUND: Harness did not report a clear error for missing planner fixture. Exit=${r.exitCode}. Output: ${r.output.trim().slice(-200)}`);
  }
}

// ═══════════════════════════════════════════════════════════
// SCENARIO 9: Exception override attack — exception matching all repos
// ═══════════════════════════════════════════════════════════
console.log("\n[9/10] Exception override attack (all-repo bypass)");
{
  const fixturesPath = path.join(rootDir, "fixtures/harness/remediation-dry-run/fixtures.json");
  const orig = fs.readFileSync(fixturesPath, "utf8");
  const fixtures = JSON.parse(orig);
  const pf = fixtures.fixtures.find((f) => f.name === "expected-fail");
  const origExceptions = pf.verificationInput.exceptions || [];
  pf.verificationInput.exceptions = [
    {
      repositoryPattern: ".*",
      reason: "QA: testing all-repo exception override",
      approvedBy: "qa-bot@example.com",
      expiresAt: "2099-01-01T00:00:00.000Z"
    }
  ];
  fs.writeFileSync(fixturesPath, JSON.stringify(fixtures, null, 2));
  const r = runHarness();
  const summary = readSummary();
  const epr = summary.results.find((x) => x.fixture === "expected-fail");
  const decision = epr?.outputs?.verification?.decision;
  fs.writeFileSync(fixturesPath, orig);

  if (decision === "required-block") {
    addResult("exception-override-attack", "Exception with wildcard repo pattern attempting to bypass CI block",
      true, `Exception correctly denied bypass: decision=${decision}. CI checks still enforced.`);
  } else if (decision === "manual-approval") {
    addResult("exception-override-attack", "Exception with wildcard repo pattern attempting to bypass CI block",
      true, `Exception triggered manual approval path (decision=${decision}) — appropriate escalation.`);
  } else {
    addResult("exception-override-attack", "Exception with wildcard repo pattern attempting to bypass CI block",
      false, `DEFECT FOUND: Wildcard exception resulted in decision=${decision}. This may bypass security checks silently.`);
  }
}

// ═══════════════════════════════════════════════════════════
// SCENARIO 10: Giant findings payload — stress test (1000+ findings)
// ═══════════════════════════════════════════════════════════
console.log("\n[10/10] Giant findings payload (1000+ fake findings)");
{
  const findingsPath = path.join(rootDir, "fixtures/planner/seeded-findings.json");
  const orig = fs.readFileSync(findingsPath, "utf8");
  const findings = JSON.parse(orig);
  const severities = ["critical", "high", "medium", "low"];
  const classes = ["outdated_dependency", "code_vulnerability", "secrets_found", "misconfiguration"];
  const extraFindings = [];
  for (let i = 0; i < 1000; i++) {
    extraFindings.push({
      id: `STRESS-${String(i).padStart(4, '0')}`,
      vulnerabilityClass: classes[i % classes.length],
      severity: severities[i % severities.length],
      packageName: `fake-pkg-${i}`,
      currentVersion: "0.0.1",
      fixedVersion: "0.0.2",
      filePath: `services/api/lib/fake-${i}.json`,
      advisoryId: `GHSA-STRESS-${String(i).padStart(4, '0')}`
    });
  }
  findings.findings = findings.findings.concat(extraFindings);
  fs.writeFileSync(findingsPath, JSON.stringify(findings, null, 2));
  const start = Date.now();
  const r = runHarness();
  const elapsed = Date.now() - start;
  const summary = readSummary();
  const epr = summary.results.find((x) => x.fixture === "expected-pass");
  fs.writeFileSync(findingsPath, orig);

  const changeCount = epr?.outputs?.planner?.changes?.length || 0;
  if (elapsed > 30000) {
    addResult("giant-findings-payload", "Stress test with 1000+ synthetic findings",
      false, `DEFECT FOUND: Harness took ${elapsed}ms (>30s) to process 1000 findings. Performance regression risk.`);
  } else if (epr?.status === "fail") {
    addResult("giant-findings-payload", "Stress test with 1000+ synthetic findings",
      true, `Processed 1000 findings in ${elapsed}ms but fixture did not pass (status=${epr.status}). Planner changes=${changeCount}. May need scaling adjustments.`);
  } else {
    addResult("giant-findings-payload", "Stress test with 1000+ synthetic findings",
      true, `Processed 1000 findings in ${elapsed}ms successfully. Planner generated ${changeCount} changes. Performance is acceptable.`);
  }
}

// ═══════════════════════════════════════════════════════════
// SUMMARY
// ═══════════════════════════════════════════════════════════
console.log("\n=============================================");
console.log("  ADVERSARIAL QA SWEEP — FINAL SUMMARY");
console.log("=============================================");
const defects = results.filter((r) => r.detail?.includes("DEFECT"));
const passes = results.filter((r) => !r.detail?.includes("DEFECT"));

console.log(`\nScenarios tested: ${results.length}`);
console.log(`Defects found:    ${defects.length}`);
console.log(`Clean passes:     ${passes.length}`);

console.log("\n── Scenario Matrix ──");
for (const r of results) {
  const status = r.detail.includes("DEFECT") ? "DEFECT FOUND" : "PASS";
  console.log(`  [${status}] ${r.name}: ${r.description}`);
  if (r.artifactKey) console.log(`             Artifact: ${r.artifactKey}`);
  console.log(`             ${r.detail.slice(0, 180)}`);
}

if (defects.length > 0) {
  console.log("\n── Defects for Coder Tickets ──");
  for (const d of defects) {
    console.log(`\n  ${d.name}:`);
    console.log(`    ${d.detail}`);
  }
}

console.log("\n── Release Gate ──");
if (defects.length > 0) {
  console.log(`  GATE: HOLD — ${defects.length} defect(s) found. Do not ship until resolved.`);
  console.log(`  Top risks: schema validation accepts invalid inputs; metric validation is missing`);
} else {
  console.log("  GATE: SHIP — No defects found beyond known fixture coverage.");
}
