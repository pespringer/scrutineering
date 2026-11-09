import test from "node:test";
import assert from "node:assert/strict";
import { createGitHubAppToken } from "./github-app-token.mjs";

test("requests a scoped GitHub App installation token", async () => {
  const result = await createGitHubAppToken({ appId: "1", installationId: "2", createJwt: async () => "jwt", fetchImpl: async (_url, options) => ({ ok: true, options, async json() { return { token: "installation-token", expires_at: "2030-01-01T00:00:00Z" }; } }) });
  assert.equal(result.token, "installation-token");
});
