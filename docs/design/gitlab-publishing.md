# GitLab publishing

Status: accepted · 2026-11-21 · Phase 6 · step 1 built

## Problem

A verified fix can be published only as a GitHub pull request (decision D4 in the
reset plan). If an image is built from a GitLab repository, the remediation stops
at `ready`. The operator has to copy the patch by hand, open a merge request,
and remember to rescan after the merge. Nothing links the merge request back to
the remediation, so a closed merge request never fails it.

## Scope

**In:**

- **Publishing to GitLab.** A `ready` remediation whose source is a GitLab
  repository is published as a merge request. It's the same operator action, at
  the same point in the loop, as a GitHub pull request:
  - push `scrutineering/remediation-<id>` with the patch as one commit on top of
    the verified commit;
  - open a merge request against the source's ref, or the project's default
    branch;
  - give it the same body: the plan and the before/after comparison.
- **One GitLab instance:** gitlab.com or a self-managed server, set by
  `GITLAB_URL`.
- **Cloning private GitLab sources** with the publishing token, as GitHub sources
  are cloned with `GITHUB_TOKEN`.
- **A merge request webhook.** A merge queues a rescan, and a close without
  merging fails the remediation, as the GitHub `pull_request` webhook does today.
- **One publisher interface.** `src/remediation/publish.py` picks the provider
  from the source URL. The GitHub code moves behind the same interface and keeps
  its behaviour.

**Out:**

- **More than one GitLab instance,** or GitLab and a second self-managed server
  at once.
- **Other hosts:** Bitbucket, Gitea, Forgejo, Azure DevOps.
- **Merge request policy.** Scrutineering doesn't set approvals, assignees,
  labels or auto-merge, and never merges. The project's own settings apply.
- **Pipeline status** on the merge request. The rescan of the rebuilt image
  decides whether the fix worked, as it does for GitHub.
- **Registry access.** `GITLAB_TOKEN`, `GITLAB_USERNAME` and `CI_JOB_TOKEN` keep
  pulling from registry.gitlab.com unchanged (see open question 1).

## Design

### Which sources publish to GitLab

A source publishes to GitLab when its repository URL is
`https://<GITLAB_URL host>/<group>/.../<project>`, optionally ending in `.git`.
Its project path, such as `team/backend/api`, is GitLab's `path_with_namespace`.
Subgroups are allowed, up to GitLab's limit of 20 levels.

Anything else on that host is rejected, as is any other host. A source on
github.com keeps publishing to GitHub. A source on neither host has no
publication target, and its patch is applied by hand as today.

`src/remediation/sources.py` gains `gitlab_project(url)`, next to
`github_repository(url)`, and one `publication_target(url) -> (provider, path)`
that the API, the serializer and the worker all use.

### The publisher interface

```python
class Provider(Protocol):
    name: str                                   # "github" or "gitlab"
    label: str                                  # "GitHub", for messages
    def token(self) -> str: ...
    def clone_url(self, path: str) -> str: ...
    def default_branch(self, path: str) -> str: ...
    def open_change(self, path: str, *, head: str, base: str, title: str, body: str) -> Change: ...

@dataclass
class Change:
    number: int        # GitHub pull number, or GitLab merge request iid
    url: str           # web URL shown on the remediation page
```

`provider_for(target)` builds the client from the environment's token, and
`sources.source_token(url)` picks the token that clones a source.

`publish()` stays one function: it loads the job, resolves the provider, pushes
the branch with `push_branch()` (already provider-neutral apart from the clone
URL and token), opens the change and records it. The GitHub class keeps its
current calls. The GitLab class uses REST API v4:

| Step | GitLab call |
|---|---|
| Default branch | `GET /api/v4/projects/:path` → `default_branch` |
| Open the merge request | `POST /api/v4/projects/:path/merge_requests` (source and target branch, title, description) |
| Already open (409) | `GET /api/v4/projects/:path/merge_requests?state=opened&source_branch=<branch>` |

`:path` is the URL-encoded `path_with_namespace`. Requests send `PRIVATE-TOKEN`.
Errors are reduced to the status and GitLab's `message` and never include the
token, as with GitHub. Git operations authenticate as `oauth2` with the token
through the existing askpass helper, so the token is never in a URL or in argv.

### Data

No migration. `remediation_publications` already has `provider`, `repository`
and `provider_number`. A GitLab publication stores `gitlab`, the project path and
the merge request iid. The unique key (provider, repository, idempotency key)
still holds with one instance.

The remediation detail gains `publication_provider` (`github` or `gitlab`) next
to `publication_target`. The dashboard button reads **Open merge request on
team/backend/api** for GitLab.

### The webhook

`POST /api/dashboard/webhooks/gitlab` accepts **Merge request events**:

- **Authentication.** GitLab sends the configured secret verbatim in
  `X-Gitlab-Token`. The API compares it to `GITLAB_WEBHOOK_SECRET` in constant
  time, and rejects requests without it.
- **Replays.** `X-Gitlab-Event-UUID` is the idempotency key, recorded in
  `remediation_webhook_events` as GitHub's delivery ID is.
- **Matching.** The publication is matched on `project.path_with_namespace`
  plus `object_attributes.iid`.
- **What it does:**
  - `action: merge` records `merged`, the merge commit and the time, and queues a
    high-priority rescan. This is the same `_closed` path as a merged GitHub pull
    request.
  - `action: close` fails a `published` remediation with "merge request !N was
    closed without merging".
  - Anything else is recorded and ignored.

`is_provider_webhook_path` admits `/webhooks/gitlab` as well as
`/webhooks/github`. The webhook only reports what happened to the merge request;
completion still comes from the server's own rescan (project rule 4).

**Without the webhook,** publication still works. A remediation completes when a
scan of the rebuilt image no longer shows its targets. Only two things are lost:
the immediate rescan after a merge, and failing a remediation whose merge request
was closed. This is the same as GitHub today, and it matters for installs that
gitlab.com can't reach.

## Configuration

| Variable | Default | Services | |
|---|---|---|---|
| `GITLAB_URL` | `https://gitlab.com` | api, worker | The one GitLab instance, `https://` only |
| `GITLAB_PUBLISH_TOKEN` 🔒 | empty | api, worker | Opens merge requests and clones private sources |
| `GITLAB_WEBHOOK_SECRET` 🔒 | empty | api | The secret set on the project's merge request webhook |

**When it's off:** with `GITLAB_PUBLISH_TOKEN` empty, publishing a GitLab source
returns `503 publication_not_configured`, as GitHub does without
`GITHUB_TOKEN`. Nothing is ever published unless an operator chooses publish.

## Security

- **Least privilege.** A project access token on the source projects, with the
  Developer role and `api` plus `write_repository`, is enough. The guide will
  say so, and warn against personal tokens.
  - A separate variable keeps this write-capable token away from the
    registry-pull code paths, which run on every scan (open question 1).
- **No server-side request forgery.** Requests go only to `GITLAB_URL`, which
  is set in the environment and never from the browser. A source URL on any
  other host can't trigger a GitLab call.
- **Self-managed servers.** They must use `https://`, and certificates are
  checked against the system trust store. A private CA is added to the image's
  trust store, not turned off with a flag.
- **The webhook secret is a shared token, not a signature.** GitLab sends it as
  is, so anyone who sees one request can replay or forge others. Event UUIDs
  stop replays. The API must be reached over TLS, and a forged request can only
  do two things:
  - trigger a rescan;
  - fail a `published` remediation whose merge request is really open. A
    retry restores it.
- **What a stolen `GITLAB_PUBLISH_TOKEN` gives:** write access to the source
  projects, the same as a stolen `GITHUB_TOKEN` today. It's held only by the api
  and worker, like the other secrets.

## Testing

- **Unit tests, with GitLab responses recorded as fixtures and no network:**
  - recognising sources: gitlab.com, a self-managed host, subgroups, `.git`,
    and rejecting other hosts, credentials in the URL and `http://`;
  - opening a merge request: created, already open (409 then lookup),
    project not found, token rejected;
  - errors never contain the token;
  - the webhook: a bad or missing token returns 401, a replayed event UUID is
    accepted once, a merge queues a rescan, a close fails the remediation, and
    an unmatched merge request is recorded;
  - the GitHub publisher's existing tests pass unchanged behind the interface.
- **Golden path:** unchanged. It publishes nothing and uses a local source.
- **Live:** a throwaway private project on gitlab.com:
  1. connect it as an image's source;
  2. run a fix through to `ready`, then publish it;
  3. merge the merge request with the webhook pointed at the API through a
     tunnel;
  4. see the rescan queued.

## Rollout

1. **Publisher interface:** `Provider`, `Change` and `publication_target`, with
   GitHub moved behind them. There's no behaviour change, and the GitHub tests
   pass as they are.
2. **GitLab publishing:**
   - `GITLAB_URL` and `GITLAB_PUBLISH_TOKEN`;
   - recognising GitLab sources;
   - cloning private ones;
   - opening the merge request;
   - `publication_provider` in the API, and the dashboard label.
3. **GitLab webhook:**
   - `GITLAB_WEBHOOK_SECRET` and `/webhooks/gitlab`;
   - an operations doc, `docs/operations/gitlab-publication.md`, next to the
     GitHub one;
   - the reset plan's D4 entry updated to say GitLab is the second provider.

## Decisions

Accepted with the recommendations on 2026-11-21:

1. **A separate `GITLAB_PUBLISH_TOKEN`.** `GITLAB_TOKEN` stays a registry credential, so
   scans never hold a write-capable token.
2. **One GitLab instance**, set by `GITLAB_URL`.
3. **Branch deletion after merge is left to the project's settings**, as with GitHub.
