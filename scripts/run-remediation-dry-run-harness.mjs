import fs from "node:fs";
import path from "node:path";
import { runRemediationDryRunHarness } from "../src/harness/remediation-dry-run-harness.mjs";

const projectRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const outputPath = path.join(projectRoot, "fixtures", "harness", "remediation-dry-run", "summary.json");

const result = runRemediationDryRunHarness({
  projectRoot,
  fixturesPath: "fixtures/harness/remediation-dry-run/fixtures.json",
  now: "2026-04-05T09:00:00.000Z",
});

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(result, null, 2)}\n`, "utf8");

console.log(outputPath);

if (result.status !== "pass") {
  console.error("Remediation dry-run harness failed.");
  process.exit(1);
}
