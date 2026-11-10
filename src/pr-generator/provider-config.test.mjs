import test from "node:test";
import assert from "node:assert/strict";
import { loadProviderConfig } from "./provider-config.mjs";

test("loads provider tokens and normalized allowlists", () => {
  const config = loadProviderConfig({
    GITHUB_TOKEN: "gh-token",
    GITHUB_ALLOWED_REPOSITORIES: " acme/api,acme/web,acme/api ",
    GITLAB_TOKEN: "gl-token",
    GITLAB_ALLOWED_PROJECTS: "12, 34",
  });
  assert.deepEqual(config.github, { token: "gh-token", allowedRepositories: ["acme/api", "acme/web"], requireBranchProtection: false });
  assert.deepEqual(config.gitlab, { token: "gl-token", allowedProjects: ["12", "34"], requireBranchProtection: false });
});

test("requires both provider allowlists in production", () => {
  assert.throws(() => loadProviderConfig({ NODE_ENV: "production", GITHUB_TOKEN: "x" }), /allowlists/);
});
