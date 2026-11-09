import test from "node:test";
import assert from "node:assert/strict";
import { evaluatePostMerge } from "./post-merge-policy.mjs";

test("post-merge policy verifies healthy deployments and requires rollback on drift", () => {
  assert.equal(evaluatePostMerge({ expectedDigest: "a", observedDigest: "a", scanStatus: "completed", before: 2, after: 1 }).status, "verified");
  assert.equal(evaluatePostMerge({ expectedDigest: "a", observedDigest: "b", scanStatus: "completed", before: 2, after: 1 }).status, "rollback_required");
});
