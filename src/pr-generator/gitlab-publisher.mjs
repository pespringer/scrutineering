export function createGitLabPublisher({ token, allowedProjects = [], fetchImpl = fetch } = {}) {
  if (!token) throw new Error("GitLab publisher token is required");
  return async function publishMergeRequest({ projectId, title, description, sourceBranch, targetBranch = "main", evidenceVerified, idempotencyKey }) {
    if (!allowedProjects.includes(String(projectId))) throw new Error("GitLab project is not allowlisted");
    if (evidenceVerified !== true) throw new Error("verified evidence is required before publication");
    if (!idempotencyKey || !title || !description || !sourceBranch || !targetBranch) throw new Error("merge request fields are required");
    const response = await fetchImpl(`https://gitlab.com/api/v4/projects/${encodeURIComponent(projectId)}/merge_requests`, {
      method: "POST", headers: { "PRIVATE-TOKEN": token, "content-type": "application/json" },
      body: JSON.stringify({ title, description, source_branch: sourceBranch, target_branch: targetBranch, labels: "security,auto-remediation" }),
    });
    if (!response.ok) throw new Error(`GitLab MR creation failed with status ${response.status}`);
    const result = await response.json();
    return { projectId: String(projectId), iid: result.iid, url: result.web_url, idempotencyKey };
  };
}
