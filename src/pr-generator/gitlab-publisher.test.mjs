import assert from "node:assert/strict";
import test from "node:test";
import { createGitLabPublisher } from "./gitlab-publisher.mjs";

test("publishes an evidence-backed allowlisted GitLab MR", async () => {
  let calls = 0;
  const publish = createGitLabPublisher({ token: "secret", allowedProjects: ["42"], fetchImpl: async () => { calls += 1; return { ok: true, async json() { return { iid: 3, web_url: "https://gitlab.com/acme/api/-/merge_requests/3" }; } }; } });
  const request = { projectId: 42, title: "Fix", description: "Details", sourceBranch: "auto/fix", evidenceVerified: true, idempotencyKey: "run-1" };
  const result = await publish(request);
  assert.deepEqual(result, { projectId: "42", iid: 3, url: "https://gitlab.com/acme/api/-/merge_requests/3", idempotencyKey: "run-1" });
  assert.deepEqual(await publish({ ...request, title: "Changed" }), result);
  assert.equal(calls, 1);
});
