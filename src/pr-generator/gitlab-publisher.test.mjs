import assert from "node:assert/strict";
import test from "node:test";
import { createGitLabPublisher } from "./gitlab-publisher.mjs";

test("publishes an evidence-backed allowlisted GitLab MR", async () => {
  const publish = createGitLabPublisher({ token: "secret", allowedProjects: ["42"], fetchImpl: async () => ({ ok: true, async json() { return { iid: 3, web_url: "https://gitlab.com/acme/api/-/merge_requests/3" }; } }) });
  assert.deepEqual(await publish({ projectId: 42, title: "Fix", description: "Details", sourceBranch: "auto/fix", evidenceVerified: true, idempotencyKey: "run-1" }), { projectId: "42", iid: 3, url: "https://gitlab.com/acme/api/-/merge_requests/3", idempotencyKey: "run-1" });
});
