# Operator guide

How to take an image from "never scanned" to "vulnerability fixed and verified" with
the dashboard (`http://localhost:3001` on the Compose stack). For how the pieces fit
together, see [ARCHITECTURE.md](ARCHITECTURE.md); for every setting, see
[CONFIGURATION.md](CONFIGURATION.md).

What you can do depends on your roles (local API-key sessions get
`DASHBOARD_DEFAULT_ROLES`):

- `dashboard`: read scans, images and findings.
- `operator`: also start, cancel and retry scans, and acknowledge findings.
- `remediator`: see remediations, connect sources, and propose, execute and cancel
  remediations.
- `security-operator`: all of the above, plus approve, accept new findings, restart
  a failed remediation, publish, and export the audit trail.
- `admin`: everything.

## 1. Scan an image

**From the bundled registry.** The stack includes an OCI registry for local images.
Push to it from your machine as `localhost:5000`; the services reach the same
registry as `registry:5000`:

```bash
docker tag my-app:1.0 localhost:5000/team/my-app:1.0
docker push localhost:5000/team/my-app:1.0
```

Open **Images**. The **Registry catalog** lists every tag in the registry with its
digest and state (`Not scanned`, `Scanning`, `Clean`, `Issues found`, `Scan failed`).
Choose **Scan image**, or **Rescan** after pushing a new build under the same tag.

The bundled registry has no authentication and speaks HTTP (`REGISTRY_INSECURE=true`
allows HTTP for it alone). Use it for local work only; shared or production
installations should scan from an authenticated TLS registry and set
`REGISTRY_INSECURE=false`.

**From any other registry.** In **Scans**, use **Run a targeted scan** with a
full reference such as `ghcr.io/acme/api:2.3` and a priority. For private images, set
the registry's credentials (see [Registry credentials](CONFIGURATION.md#registry-credentials));
ECR and GCR use the standard AWS and Google credentials.

**Automatically.**
- Every known image is rescanned on `SCHEDULE_CRON_SCAN` (every 6 hours by default),
  skipping images scanned within `SCAN_COOLDOWN_SECONDS`.
- Runtime discovery can also scan the images of running containers every 15
  minutes. It is off by default because it needs access to the host's Docker socket
  or containerd. To turn it on, set `SCAN_RUNTIME_DISCOVERY_ENABLED=true` (plus the
  include and exclude filters in [Runtime discovery](CONFIGURATION.md#runtime-discovery)),
  then start the worker with the Docker overlay:

  ```bash
  export DOCKER_SOCKET_GID="$(stat -c '%g' /var/run/docker.sock)"
  docker compose -f docker-compose.yml -f docker-compose.deployment-docker.yml \
    up --build -d celery-worker celery-beat
  ```

Each scan first resolves the tag to its digest and scans that digest, so the result
always belongs to one exact image. Trivy and Grype run side by side, and their
findings are merged.

## 2. Read a scan

The scan page shows the scan's phase, digest, scanner versions, and findings. It
refreshes itself while the scan runs.

- **`pending`, `running`**: queued or in progress. Either can be cancelled.
- **`completed`**: every scanner succeeded. Findings no longer present are marked
  resolved.
- **`partial`**: at least one scanner failed. Findings are recorded, but nothing is
  resolved, because the scan may have missed things. The error names the scanner.
- **`failed`**: every scanner failed, or the results could not be saved. The error
  says why.
- **`cancelled`**: stopped by an operator.

## 3. Triage findings

Open the image from **Images**. Its findings are tracked across scans, not per scan:
each one has a first-seen and last-seen time, and it is **resolved** when a complete
scan no longer sees it. If it comes back, it is reopened. The open and resolved
counts tell "the risk is gone" apart from "nothing was scanned".

- Filter by severity, and sort by severity, CVE, package, version or first seen.
  Findings with a fixed version are the ones a remediation can fix automatically.
- Select findings, then **Acknowledge** them to mark them as reviewed.
- `GET /api/dashboard/findings/export` exports findings (filters: severity,
  acknowledged, image) for other tools.

## 4. Connect the image's source

A remediation patches the source the image is built from, so the image must know
where that is. On the image page, open **Source → Connect source** and set:

- **Repository:** either an `https://` git URL, or a folder under the worker's
  sources directory (`REMEDIATION_HOST_SOURCES`, `./.local/remediation-sources` by
  default, mounted read-only). Private github.com repositories are cloned with
  `GITHUB_TOKEN`.
- **Ref:** the branch, tag or commit the image is built from (`HEAD` by default).
- **Dockerfile** and **build context**, relative to the repository.
- **Test command** (optional): a JSON list of arguments such as `["npm", "test"]`.
  It runs inside the patched image before it is scanned, so the tools it calls must
  be in the image; a non-zero exit fails the fix.
- **Build arguments**, if the build needs any (set through
  `PUT /api/dashboard/images/{id}/source`; the form keeps them).

## 5. Propose a fix

Select findings on the image page and choose **Propose remediation**. From a scan's
findings, choose **Propose fixes**. Scrutineering decides how each finding can be
fixed and proposes the ones it can:

- **npm and pip packages:** update the dependency (lockfile included).
- **OS packages (apk, apt, rpm):** add an upgrade step to the final stage of the
  Dockerfile.
- **Runtime binaries from the base image** (for example `node`): move the final
  `FROM` to the newest tag of the same release line.
- **No fixed version, or an unsupported ecosystem:** left out, and the message says
  how many need a manual fix.

The details are in [remediation execution](operations/remediation-execution.md). A
finding can be in only one open remediation at a time.

## 6. Approve and build

Open the remediation from **Remediations**.

1. A **security operator** reviews the proposed changes and chooses **Approve**.
2. **Build and verify** starts execution. It needs `REMEDIATION_EXECUTION_ENABLED=true`.
   The worker:
   1. clones the source into a temporary directory;
   2. applies the changes;
   3. builds the patched image on the rootless `buildkitd` service and pushes it to
      the local registry as `scrutineering-candidate-<id>`;
   4. runs the source's test command inside it, if it has one;
   5. scans it with the same scanners.

   The status moves through `building` and `verifying`, and the page refreshes
   itself.

## 7. Read the result

The **Candidate image** panel shows the candidate's digest, how many of the targeted
findings it still has, any new critical or high findings, and the patch.

- **`ready`**: the candidate has none of the targeted findings and adds nothing
  critical or high. Ship the fix (step 8).
- **`needs_acceptance`**: the targets are gone, but the candidate adds critical or
  high findings, which are listed. This is typical of a base-image bump. A security
  operator chooses **Accept new findings** (→ `ready`) or **Cancel**.
- **`failed`**: something stopped it, and the reason is shown. Causes include: no
  source, a clone or apply failure, a build error (with the end of the build log),
  failing tests (with the end of their output), an incomplete candidate scan, or
  targets still present. Fix the cause, then **Restart workflow**: it returns to
  `proposed` and needs approval again.

**Cancel** works at any point before `completed`, and releases the findings so they
can be proposed again.

## 8. Ship the fix

The fix is in the candidate image, not in your source or your running image yet.
Choose one way:

- **Open a pull request** (github.com sources). A security operator chooses **Open
  pull request on owner/name**. Scrutineering pushes `scrutineering/remediation-<id>`
  and opens a pull request with the plan and the before/after comparison. The
  remediation becomes `published`. Setup (token permissions and the merge webhook)
  is in [GitHub publication](operations/github-publication.md).
- **Apply the patch yourself.** Copy the patch from the Candidate image panel and
  apply it to the source at the commit shown.

Then rebuild the image from the updated source and push it under the same tag. The
next complete scan of that tag (a manual **Rescan**, the schedule, or the rescan the
merge webhook queues) decides the outcome:

- None of the targeted findings remain: the remediation is **`completed`**, and the
  findings are resolved.
- A published fix whose image was rebuilt (new digest) still has a targeted finding:
  **`failed`**, with the reason.
- The image has not been rebuilt yet (same digest): it stays `published` and waits.

If the pull request is closed without merging, the remediation is `failed`.

## 9. The audit trail

**Audit** lists operator actions and scan lifecycle events with who, when and what:
scans started and cancelled, sources connected, remediations approved, executed,
accepted, published and cancelled. Export it with `GET /api/dashboard/audit/export`.
Exporting needs the `security-operator` role. Each remediation also has its own event
timeline on its page.

## 10. Notifications

Scrutineering can post a message when a remediation needs someone or finishes:
`proposed` (approve it), `needs_acceptance` (accept or cancel it), `ready` (publish
it or rebuild the image), `published` (with the pull request link), `completed`
and `failed` (with the reason's first line). Choose which with `NOTIFICATION_EVENTS`.

To turn it on, set these in `.env` and restart the stack (`make up`):

```bash
NOTIFICATION_WEBHOOK_URL=https://ntfy.example.com/hooks/scrutineering
NOTIFICATION_WEBHOOK_SECRET=<a long random string>
DASHBOARD_PUBLIC_URL=https://scrutineering.home.lan   # optional: links in messages
```

The URL must be `https://`, or `http://` to a private address (such as
`http://192.168.1.20:8080/hook`) or a single-label host name (such as
`http://ntfy/scrutineering`). The worker must consume the `notify` queue, which
the default `CELERY_QUEUES` includes.

Each message is a JSON `POST`:

```json
{
  "id": 412,
  "event": "remediation.published",
  "occurred_at": "2026-11-17T14:03:11Z",
  "remediation": {
    "id": 57, "status": "published", "label": "Pull request open",
    "image": "registry:5000/shop/api:1.4.2", "action": "dependency_update", "targets": 3,
    "new_critical_high": [], "pull_request_url": "https://github.com/shop/api/pull/9",
    "error": null, "url": "https://scrutineering.home.lan/remediations/57"
  }
}
```

The headers are:

- `X-Scrutineering-Event`: the event.
- `X-Scrutineering-Delivery`: the `id`.
- `X-Scrutineering-Signature`: `sha256=` and the HMAC-SHA256 of the raw body with
  your secret.

Verify the signature before trusting a message:

```python
import hashlib, hmac

def verified(secret: bytes, body: bytes, header: str) -> bool:
    expected = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header)
```

How delivery behaves:

- Delivery is at least once, so drop repeats by `id`.
- A receiver that doesn't answer 2xx within 10 seconds is retried after 1, 5, 15
  and 60 minutes. After the fifth failed attempt the message is marked `failed`.
- Redirects are not followed.

Messages name images, CVEs and pull requests, so send them only to a private
channel. The URL and secret are credentials: they're never logged or shown, and
only the environment can set them.

## Troubleshooting

- **The dashboard shows an API error, or the header shows a degraded service.**
  Check `curl localhost:8000/health` (process up) and `curl localhost:8000/ready`
  (database reachable), then `docker compose ps` and the failing service's logs.
- **A scan of `localhost:5000/...` fails.** Inside the stack, `localhost` is the
  worker itself. Scan `registry:5000/...`.
- **A scan fails with `invalid configuration: ...`.** A setting has an invalid value,
  and the message names it. Fix it in `.env` and restart.
- **"Connect this image's source repository before proposing fixes."** See step 4.
- **"None of the selected findings can be fixed automatically."** There is no fixed
  version yet, or the ecosystem is unsupported. Fix by hand, or wait for a fix.
- **Build and verify returns `remediation_execution_disabled`.** Set
  `REMEDIATION_EXECUTION_ENABLED=true` and restart the API.
- **`failed`: "is not a git repository under the sources root".** The folder must be
  a git repository inside `REMEDIATION_HOST_SOURCES`.
- **`failed` with a git clone error for a github.com source.** For a private
  repository, `GITHUB_TOKEN` must be able to read it.
- **The build fails at once with a user-namespace error.** Rootless BuildKit needs
  unprivileged user namespaces (`/proc/sys/user/max_user_namespaces` above 0).
- **Publishing returns `publication_not_configured` or `source_not_on_github`.** Set
  `GITHUB_TOKEN`; the source must be an `https://github.com/...` URL.
- **Publication failed: the branch "already exists on GitHub with other commits".**
  Someone else pushed to `scrutineering/remediation-<id>`. Delete that branch and
  publish again.
- **A merged remediation stays `published`.** The image has not been rebuilt and
  pushed under the scanned tag yet. A scan of the new digest settles it.
- **No notifications arrive.** Check that `CELERY_QUEUES` includes `notify`, then look
  at the outbox. `last_error` is the receiver's status code or the connection error.

  ```bash
  docker compose exec postgres psql -U scrutineering -c \
    "select id, event, status, attempts, last_error from notifications order by id desc limit 10"
  ```

To remove all local test images, stop the stack and delete the registry volume:
`docker compose down && docker volume rm scrutineering_registrydata`.
