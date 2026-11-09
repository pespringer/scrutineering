# GitHub Publication Boundary

`createGitHubPublisher` is a deliberately narrow PR adapter. It requires an
allowlisted `owner/repo`, non-empty branch metadata, and `evidenceVerified:
true` before calling GitHub. It uses the GitHub JSON API and never logs the
token.

Production should use a GitHub App installation token scoped to pull-request
creation and contents read/write for the target repositories. Publication
requires an idempotency key, protects `main`/`master`, and reuses a prior
result for duplicate keys within the publisher process. The adapter does not
merge, approve, bypass branch protection, or support arbitrary repository
coordinates.

The GitLab adapter applies the same default `main`/`master` target-branch
policy and permits a narrower configured list when a repository uses a
different protected branch.
