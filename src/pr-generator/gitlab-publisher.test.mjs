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
  await assert.rejects(() => publish({ ...request, targetBranch: "feature", idempotencyKey: "run-2" }), /protected/);
  await assert.rejects(() => publish({ ...request, sourceBranch: "../bad", idempotencyKey: "run-3" }), /branch/);
});

test("supports an external idempotency store", async () => {
  const records = new Map(); let calls = 0;
  const publish = createGitLabPublisher({ token: "secret", allowedProjects: ["42"], idempotencyStore: { get: async (key) => records.get(key), set: async (key, value) => records.set(key, value) }, fetchImpl: async () => { calls += 1; return { ok: true, async json() { return { iid: 4, web_url: "https://gitlab.test/mr/4" }; } }; } });
  const request = { projectId: 42, title: "Fix", description: "Details", sourceBranch: "auto/fix", evidenceVerified: true, idempotencyKey: "external" };
  await publish(request); await publish(request); assert.equal(calls, 1);
});
