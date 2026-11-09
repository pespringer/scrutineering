export function createGitLabPublisher({ token, allowedProjects = [], allowedTargetBranches = ["main", "master"], fetchImpl = fetch } = {}) {
  if (!token) throw new Error("GitLab publisher token is required");
  const published = new Map();
  return async function publishMergeRequest({ projectId, title, description, sourceBranch, targetBranch = "main", evidenceVerified, idempotencyKey }) {
    const normalizedProjectId = String(projectId);
    if (!allowedProjects.includes(normalizedProjectId)) throw new Error("GitLab project is not allowlisted");
    if (!allowedTargetBranches.includes(targetBranch)) throw new Error("target branch is not protected by publication policy");
    if (evidenceVerified !== true) throw new Error("verified evidence is required before publication");
    if (!idempotencyKey || !title || !description || !sourceBranch || !targetBranch) throw new Error("merge request fields are required");
    const key = `${normalizedProjectId}:${idempotencyKey}`;
    if (published.has(key)) return published.get(key);
    const response = await fetchImpl(`https://gitlab.com/api/v4/projects/${encodeURIComponent(normalizedProjectId)}/merge_requests`, {
      method: "POST", headers: { "PRIVATE-TOKEN": token, "content-type": "application/json" },
      body: JSON.stringify({ title, description, source_branch: sourceBranch, target_branch: targetBranch, labels: "security,auto-remediation" }),
    });
    if (!response.ok) throw new Error(`GitLab MR creation failed with status ${response.status}`);
    const result = await response.json();
    const publication = { projectId: normalizedProjectId, iid: result.iid, url: result.web_url, idempotencyKey };
    published.set(key, publication);
    return publication;
  };
}
