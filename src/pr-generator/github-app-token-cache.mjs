import { createGitHubAppToken } from "./github-app-token.mjs";

export function createGitHubAppTokenProvider(options) {
  let cached = null;
  let refreshing = null;
  return async () => {
    if (cached && Number.isFinite(new Date(cached.expiresAt).getTime()) && new Date(cached.expiresAt).getTime() - Date.now() > 60_000) return cached.token;
    if (!refreshing) refreshing = createGitHubAppToken(options).finally(() => { refreshing = null; });
    cached = await refreshing;
    return cached.token;
  };
}
