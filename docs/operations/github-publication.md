# GitHub publication

A verified remediation can be published as a GitHub pull request. GitHub is the
only provider (decision D4). Publishing never merges anything, and it only
happens when a security operator asks for it.

## Setup

1. **The image's source is on github.com.** Its repository (see
   [remediation execution](remediation-execution.md)) must be an
   `https://github.com/<owner>/<name>` URL.
2. **`GITHUB_TOKEN`** in `.env`, for the worker. Use a fine-grained token (or a
   GitHub App installation token) limited to the source repositories, with
   **Contents: read and write** and **Pull requests: read and write**. The token's
   repository selection is the allowlist: publication cannot reach a repository the
   token cannot. The same variable also authenticates scans of `ghcr.io` images;
   setting it does not publish anything by itself.
3. **The webhook**, so merges are noticed. In the repository's **Settings →
   Webhooks**, add `https://<api host>/api/dashboard/webhooks/github` with content
   type `application/json`, the secret from `GITHUB_WEBHOOK_SECRET`, and only the
   **Pull requests** event. For a local stack, expose the API through a tunnel (for
   example `cloudflared tunnel --url http://127.0.0.1:8000`).

## Publishing

On a `ready` remediation, **Open pull request** (`POST /remediations/{id}/publish`,
security-operator) queues the publication on the worker. The worker:

1. Clones the repository and checks out `source_commit`, the commit the remediation
   patched.
2. Applies the stored `patch` and commits it as `Scrutineering`, with a fixed
   timestamp so a retried publication produces the same commit.
3. Pushes it to `scrutineering/remediation-<id>`. It only overwrites that branch if
   the branch still holds the commit Scrutineering pushed last time, so it never
   replaces someone else's commits.
4. Opens a pull request against the source's ref (or the repository's default
   branch when the ref is `HEAD` or a commit). If one is already open for the
   branch, that one is used.

The pull request body lists the targeted findings, the planned changes, and the
open findings on the image now against those on the verified candidate image. The
remediation becomes `published` and the pull request is recorded on it.

If any step fails, the publication is recorded as failed with the reason and the
remediation stays `ready`, so it can be published again. The token is passed to git
through `GIT_ASKPASS`, never in a URL or argument, and never appears in errors.

## After the pull request

The webhook (`X-Hub-Signature-256` HMAC, replay-protected by `X-GitHub-Delivery`)
only reports what happened to the pull request. Nothing else in the payload is
trusted.

- **Merged:** the publication is marked merged and a rescan of the image is queued.
- **Closed without merging:** the remediation is `failed`.

Merging changes the source, not the running image. The server decides the outcome
from its own complete scans of the image:

- No targeted finding remains: `completed`.
- The image's digest differs from its digest when the pull request was opened (it
  was rebuilt), and a targeted finding remains: `failed`, with the reason.
- The digest is unchanged: still `published`, waiting for the rebuilt image. The
  scheduled scans pick it up.
