import { evaluatePostMerge } from "../src/remediation/post-merge-policy.mjs";

const scenarios = [
  { name: "healthy deployment", expectedDigest: "sha256:good", observedDigest: "sha256:good", scanStatus: "completed", before: 3, after: 1, expected: "verified" },
  { name: "digest drift", expectedDigest: "sha256:good", observedDigest: "sha256:bad", scanStatus: "completed", before: 3, after: 1, expected: "rollback_required" },
  { name: "finding regression", expectedDigest: "sha256:good", observedDigest: "sha256:good", scanStatus: "completed", before: 1, after: 2, expected: "rollback_required" },
];
for (const scenario of scenarios) {
  const result = evaluatePostMerge(scenario);
  if (result.status !== scenario.expected) throw new Error(`${scenario.name} expected ${scenario.expected}, got ${result.status}`);
  console.log(`PASS ${scenario.name}: ${result.status}`);
}
