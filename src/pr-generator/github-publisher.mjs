const REPOSITORY_PART = /^[A-Za-z0-9_.-]+$/;
const BRANCH_PART = /^[A-Za-z0-9._/-]{1,256}$/;

function validateRepository(owner, repo, allowedRepositories) {
  if (!REPOSITORY_PART.test(owner) || !REPOSITORY_PART.test(repo)) {
    throw new Error("invalid GitHub repository coordinates");
  }
  const fullName = `${owner}/${repo}`;
  if (allowedRepositories?.length && !allowedRepositories.includes(fullName)) {
    throw new Error("GitHub repository is not allowlisted");
  }
  return fullName;
}

export function createGitHubPublisher({ token, allowedRepositories = [], fetchImpl = fetch, idempotencyStore } = {}) {
  if (!token) throw new Error("GitHub publisher token is required");
  const published = new Map();
  return async function publishPullRequest({ owner, repo, title, body, head, base = "main", evidenceVerified, idempotencyKey }) {
    const fullName = validateRepository(owner, repo, allowedRepositories);
    if (evidenceVerified !== true) throw new Error("verified evidence is required before publication");
    if (base !== "main" && base !== "master") throw new Error("base branch is not protected by publication policy");
    if (head === base) throw new Error("head and base branches must differ");
    if (!BRANCH_PART.test(head) || !BRANCH_PART.test(base) || head.includes("..")) throw new Error("invalid branch name");
    if (!idempotencyKey) throw new Error("idempotencyKey is required for publication");
    const key = `${fullName}:${idempotencyKey}`;
    const existing = idempotencyStore ? await idempotencyStore.get(key) : published.get(key);
    if (existing) return existing;
    for (const [name, value] of Object.entries({ title, body, head, base })) {
      if (typeof value !== "string" || value.trim() === "") throw new Error(`${name} is required`);
    }
    const response = await fetchImpl(`https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/pulls`, {
      method: "POST",
      headers: {
        accept: "application/vnd.github+json",
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
        "x-github-api-version": "2022-11-28",
      },
      body: JSON.stringify({ title, body, head, base }),
    });
    if (!response.ok) throw new Error(`GitHub PR creation failed with status ${response.status}`);
    const result = await response.json();
    const publication = { repository: fullName, number: result.number, url: result.html_url };
    published.set(`${fullName}:${idempotencyKey}`, publication);
    if (idempotencyStore) await idempotencyStore.set(key, publication);
    return publication;
  };
}
