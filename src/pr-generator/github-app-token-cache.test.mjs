import test from "node:test";
import assert from "node:assert/strict";
import { createGitHubAppTokenProvider } from "./github-app-token-cache.mjs";

test("reuses an unexpired GitHub App token", async () => {
  let calls = 0;
  const token = createGitHubAppTokenProvider({ appId: "1", installationId: "2", createJwt: async () => "jwt", fetchImpl: async () => ({ ok: true, async json() { calls += 1; return { token: "token", expires_at: "2999-01-01T00:00:00Z" }; } }) });
  assert.equal(await token(), "token"); assert.equal(await token(), "token"); assert.equal(calls, 1);
});

test("coalesces concurrent token refreshes", async () => {
  let calls = 0;
  const token = createGitHubAppTokenProvider({ appId: "1", installationId: "2", createJwt: async () => "jwt", fetchImpl: async () => {
    calls += 1;
    await new Promise((resolve) => setTimeout(resolve, 5));
    return { ok: true, async json() { return { token: "token", expires_at: "2999-01-01T00:00:00Z" }; } };
  } });
  await Promise.all([token(), token(), token()]);
  assert.equal(calls, 1);
});
