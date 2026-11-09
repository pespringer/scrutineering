import { createGitHubAppToken } from "./github-app-token.mjs";

export function createGitHubAppTokenProvider(options) {
  let cached = null;
  return async () => {
    if (cached && new Date(cached.expiresAt).getTime() - Date.now() > 60_000) return cached.token;
    cached = await createGitHubAppToken(options);
    return cached.token;
  };
}
