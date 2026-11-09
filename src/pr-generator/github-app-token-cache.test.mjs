import test from "node:test";
import assert from "node:assert/strict";
import { createGitHubAppTokenProvider } from "./github-app-token-cache.mjs";

test("reuses an unexpired GitHub App token", async () => {
  let calls = 0;
  const token = createGitHubAppTokenProvider({ appId: "1", installationId: "2", createJwt: async () => "jwt", fetchImpl: async () => ({ ok: true, async json() { calls += 1; return { token: "token", expires_at: "2999-01-01T00:00:00Z" }; } }) });
  assert.equal(await token(), "token"); assert.equal(await token(), "token"); assert.equal(calls, 1);
});
