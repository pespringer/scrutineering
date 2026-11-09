export async function createGitHubAppToken({ appId, installationId, createJwt, fetchImpl = fetch } = {}) {
  if (!appId || !installationId || typeof createJwt !== "function") throw new Error("GitHub App identity and JWT signer are required");
  const response = await fetchImpl(`https://api.github.com/app/installations/${encodeURIComponent(installationId)}/access_tokens`, {
    method: "POST", headers: { accept: "application/vnd.github+json", authorization: `Bearer ${await createJwt({ appId })}`, "x-github-api-version": "2022-11-28" },
  });
  if (!response.ok) throw new Error(`GitHub App token request failed with status ${response.status}`);
  const payload = await response.json();
  if (!payload.token || !payload.expires_at) throw new Error("GitHub App token response is incomplete");
  return { token: payload.token, expiresAt: payload.expires_at };
}
