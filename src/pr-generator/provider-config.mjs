const splitList = (value) => String(value || "")
  .split(",")
  .map((entry) => entry.trim())
  .filter(Boolean)
  .filter((entry, index, entries) => entries.indexOf(entry) === index);

export function loadProviderConfig(env = process.env) {
  const githubRepositories = splitList(env.GITHUB_ALLOWED_REPOSITORIES);
  const gitlabProjects = splitList(env.GITLAB_ALLOWED_PROJECTS);
  const githubToken = String(env.GITHUB_TOKEN || "").trim();
  const gitlabToken = String(env.GITLAB_TOKEN || env.CI_JOB_TOKEN || "").trim();
  if (env.NODE_ENV === "production" && (githubRepositories.length === 0 || gitlabProjects.length === 0)) {
    throw new Error("production provider configuration requires GitHub and GitLab allowlists");
  }
  return {
    github: { token: githubToken, allowedRepositories: githubRepositories },
    gitlab: { token: gitlabToken, allowedProjects: gitlabProjects },
  };
}
