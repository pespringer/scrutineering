# GitLab Publication Boundary

The GitLab adapter mirrors the guarded GitHub boundary: project IDs must be
allowlisted and verified evidence plus an idempotency key are required before
creating a merge request. Use a narrowly scoped project access token or
GitLab OAuth integration in production.
