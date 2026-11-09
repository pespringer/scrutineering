import assert from "node:assert/strict";
import test from "node:test";
import { createGitHubPublisher } from "./github-publisher.mjs";

test("publishes only allowlisted, evidence-backed repositories", async () => {
  const calls = [];
  const publish = createGitHubPublisher({
    token: "secret",
    allowedRepositories: ["acme/api"],
    fetchImpl: async (...args) => {
      calls.push(args);
      return { ok: true, async json() { return { number: 7, html_url: "https://github.com/acme/api/pull/7" }; } };
    },
  });
  const result = await publish({ owner: "acme", repo: "api", title: "Fix", body: "Details", head: "auto/fix", evidenceVerified: true });
  assert.deepEqual(result, { repository: "acme/api", number: 7, url: "https://github.com/acme/api/pull/7" });
  assert.equal(calls[0][1].headers.authorization, "Bearer secret");
});

test("blocks unverified or disallowed publication", async () => {
  const publish = createGitHubPublisher({ token: "secret", allowedRepositories: ["acme/api"], fetchImpl: async () => ({ ok: true }) });
  await assert.rejects(() => publish({ owner: "acme", repo: "api", title: "Fix", body: "Details", head: "auto/fix" }), /verified evidence/);
  await assert.rejects(() => publish({ owner: "other", repo: "api", title: "Fix", body: "Details", head: "auto/fix", evidenceVerified: true }), /allowlisted/);
});
