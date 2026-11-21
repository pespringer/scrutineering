# Operator guide

How to take an image from "never scanned" to "vulnerability fixed and verified" with
the dashboard (`http://localhost:3001` on the Compose stack). For how the pieces fit
together, see [ARCHITECTURE.md](ARCHITECTURE.md); for every setting, see
[CONFIGURATION.md](CONFIGURATION.md).

What you can do depends on your roles (local API-key sessions get
`DASHBOARD_DEFAULT_ROLES`). Any role can read scans, images, findings, posture and
reports. Beyond that, each role may do the following, and `admin` may do everything.
The table is generated from `src/api/roles.py` (`python -m src.api.roles`).

<!-- roles:start -->
| Action | `dashboard` | `operator` | `remediator` | `security-operator` | `admin` |
|---|---|---|---|---|---|
| Browse the registry catalog (`registry.view`) | ✓ | ✓ |  | ✓ | ✓ |
| Export open findings (`findings.export`) | ✓ | ✓ |  | ✓ | ✓ |
| Start, cancel, retry and archive scans (`scans.manage`) |  | ✓ |  | ✓ | ✓ |
| Archive images (`images.archive`) |  | ✓ |  | ✓ | ✓ |
| Acknowledge and assign findings (`findings.triage`) |  | ✓ |  | ✓ | ✓ |
| See remediations, their events and evidence (`remediations.view`) |  |  | ✓ | ✓ | ✓ |
| Preview and propose a fix (`remediations.propose`) |  |  | ✓ | ✓ | ✓ |
| Build and rescan an approved fix (`remediations.execute`) |  |  | ✓ | ✓ | ✓ |
| Cancel a remediation (`remediations.cancel`) |  |  | ✓ | ✓ | ✓ |
| Connect and disconnect an image's source (`sources.manage`) |  |  | ✓ | ✓ | ✓ |
| Approve a proposed fix (`remediations.approve`) |  |  |  | ✓ | ✓ |
| Accept a fix's new critical or high findings (`remediations.accept`) |  |  |  | ✓ | ✓ |
| Open the fix's pull request (`remediations.publish`) |  |  |  | ✓ | ✓ |
| Restart a failed remediation (`remediations.retry`) |  |  |  | ✓ | ✓ |
| Export the audit trail (`audit.export`) |  |  |  | ✓ | ✓ |
| Build and download compliance exports (`compliance.export`) |  |  |  | ✓ | ✓ |
| See notification channels and send a test (`notifications.manage`) |  |  |  | ✓ | ✓ |
| Build a report on demand (`reports.build`) |  |  |  |  | ✓ |
<!-- roles:end -->

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
- **Runtime discovery** finds the images of the containers running on this host,
  every 15 minutes. It is **on by default**. Each run:
  - records which images are running: the **Running** badge and the **Running
    only** filter on the Images page;
  - on Docker, records each of their containers and the build it runs, and marks a
    container gone when it's no longer listed. A run that can't reach Docker marks
    nothing gone. An image's page lists its **Containers**, each **current** (it runs
    the build of the image's latest scan), **stale** (an older build: recreate it from
    the current tag) or **unknown** (the latest scan has no digest). The Images list
    shows "1 container · 1 stale";
  - queues a scan only of an image never scanned, or last scanned before
    `SCAN_COOLDOWN_SECONDS`, with no scan already pending or running. New
    containers are scanned within 15 minutes; the schedule keeps them current;
  - skips, and counts, images the scanners can't pull: images whose registry
    doesn't know them (built on this host) or refuses access, and containers that
    show only an image ID;
  - never scans a container labelled `scrutineering.scan=false`.

  The system status panel shows the last run ("Discovery: 5 running images, 4 not
  scannable"). If Docker can't be reached, the status turns **Degraded** with the
  error, rather than reporting nothing running.

  The worker reaches Docker only through `docker-proxy`, which mounts the socket
  read-only and allows only listing and inspecting containers and images. It
  refuses creating, starting, exec, builds and pulls with `403`, and only the
  worker can reach it. **One trade-off:** inspecting a container shows its
  environment variables, so the worker can read secrets that other containers on
  this host keep there. If that matters, or you don't want this host's
  containers listed at all, set `SCAN_RUNTIME_DISCOVERY_ENABLED=false`. For
  rootless Docker, point `DOCKER_SOCKET` at its socket
  (`$XDG_RUNTIME_DIR/docker.sock`).

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

A completed or partial image scan also has an **SBOM**: every component in the
image, as CycloneDX JSON. Download it from the scan page, or from the image page
(the latest scan's). Trivy writes it right after the scan from its own cache, so it
costs seconds. If that step fails, the scan still stands, and its completion event
records `sbom: failed`. Each image keeps its newest SBOM; older ones are removed
daily. Each SBOM is signed; see [Verifying exports](#verifying-exports).

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
   With separation of duties on, the person who proposed the fix can't approve it,
   and the button says so.
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
  `proposed` and needs approval again. The person who restarts it counts as its
  proposer.

**Who did what.** Under "What happens next", the page lists who proposed, approved,
built, accepted and published the fix, by their sign-in identity.

**Separation of duties** (`REMEDIATION_SEPARATE_APPROVER`) stops one person from
shipping a fix alone: whoever proposed a fix can't approve it, or accept its new
critical or high findings. Admins are bound by it too. The default, `auto`, turns
it on when people sign in (`DASHBOARD_AUTH_MODE=trusted-proxy`) and off in `local`
mode, where every session shares the API key's identity. A one-person sign-in
setup can set it to `off`.

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

**Evidence.** Within a minute of a remediation completing or failing, its page shows
an **Evidence** panel. It holds one signed JSON file with everything that happened:
- the targeted findings and the plan;
- the patch and the commit it applies to;
- the candidate image, its test command and verification;
- the pull request;
- the scans before and after, with their SBOM hashes, and which targets the last
  scan still saw;
- the event timeline.

It's built from Scrutineering's own records and frozen; a retry that ends again gets a
new one. Downloading it needs the remediator role, because it includes the patch.

**Deployed.** A completed remediation's page also says how many of the image's running
containers run a build with the fix ("1 of 2 containers run the fixed build") and names
the others. A fixed build is the one the completing scan saw, or a later complete scan
that still doesn't show the targets. Completed means the registry is fixed; this panel
is what tells you the running containers have picked it up.

## 9. The audit trail

**Audit** lists operator actions and scan lifecycle events with who, when and what:
scans started and cancelled, sources connected, remediations approved, executed,
accepted, published and cancelled. Export it with `GET /api/dashboard/audit/export`.
Exporting needs the `security-operator` role. Each remediation also has its own event
timeline on its page.

## 10. Reports

Every Monday at 07:00 UTC the worker builds a **weekly report** of the week before
(Monday to Monday, UTC) and signs it like an SBOM. **Reports** lists them; each page
shows:
- posture when it was built: open findings by severity, fixable, images and running
  images;
- the week's new, resolved and reopened findings, and its scans;
- the fixes that completed or failed in the week, each with its signed evidence;
- containers still on an older build, and fixes not running everywhere yet;
- the 10 images with the most open critical and high findings.

Download `report.json` with its **signature** and **public key** to keep or forward
it (see [Verifying exports](#verifying-exports)); the browser's Print gives a paper
copy. When a channel is configured, a `report_ready` notification posts the headline
numbers and a link. Change the schedule with `REPORT_SCHEDULE_CRON` (five cron fields
in UTC, or `off`). An admin can **Build report now** for this week so far; it never
replaces the weekly one.

**Compliance export.** Security operators can export a range of UTC days (up to 366)
from the same page. The worker builds one zip, kept for 24 hours, holding:
- `evidence/`: the evidence bundles that ended in the range, with their signatures;
- `sboms/`: the SBOMs those bundles cite;
- `reports/`: the reports whose period starts in the range;
- `findings.csv`: findings open now, plus those resolved in the range. A cell that a
  spreadsheet would run as a formula (starting with `=`, `+`, `-` or `@`) is prefixed
  with `'`;
- `audit.json`: the audit records in the range, with their hash chain;
- `keys/`: every public key that signed something in it;
- `manifest.json` and `manifest.json.sig`: every file's SHA-256 and size, signed.

One export runs at a time. If the signing key can't be used, the export fails rather
than shipping unsigned.

## 11. Notifications

Scrutineering can post a message when a remediation needs someone or finishes:
`proposed` (approve it), `needs_acceptance` (accept or cancel it), `ready` (publish
it or rebuild the image), `published` (with the pull request link), `completed`
and `failed` (with the reason's first line). It also sends `deployment_stale` once,
when a fix completed 24 hours ago but some running containers still run an older
build; the message names them. Fixes completed more than 72 hours ago are never
announced, so setting up a channel later doesn't post old ones. Choose which with
`NOTIFICATION_EVENTS`.

There are two channels. Set either or both in `.env`, then restart the stack
(`make up`):

```bash
# Slack: an incoming webhook (Slack app > Incoming Webhooks > Add New Webhook)
NOTIFICATION_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
# Any other receiver: signed JSON
NOTIFICATION_WEBHOOK_URL=https://ntfy.example.com/hooks/scrutineering
NOTIFICATION_WEBHOOK_SECRET=<a long random string>
# Optional, for both: links to the remediation in messages
DASHBOARD_PUBLIC_URL=https://scrutineering.home.lan
```

Each channel's messages are retried and recorded separately. The worker must
consume the `notify` queue, which the default `CELERY_QUEUES` includes.

Then open **Notifications** in the menu (security operators). It shows which
channels are configured, which statuses send messages, and the last 20 deliveries
with any error. **Send test** sends a sample message to each configured channel
through the normal delivery path and shows, within a few seconds, whether it was
sent. A refused test is marked "retrying" with the error, and it keeps retrying
in the background like any other message.

**Slack.** Each message names the image, status, action and number of targeted
findings. It also lists any new critical/high CVEs (the first five) and the reason
for a failure. Buttons link to the remediation (when `DASHBOARD_PUBLIC_URL` is set)
and the pull request. The URL must start with `https://hooks.slack.com/`. If Slack
refuses a message, `last_error` shows Slack's code, such as `HTTP 404 no_service`
for a webhook that was removed.

**Webhook.** The URL must be `https://`, or `http://` to a private address (such
as `http://192.168.1.20:8080/hook`) or a single-label host name (such as
`http://ntfy/scrutineering`). Each message is a JSON `POST`:

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

## 12. Sign-in

Out of the box (`DASHBOARD_AUTH_MODE=local`) there is no sign-in: anyone who can
reach the dashboard gets `DASHBOARD_DEFAULT_ROLES`. That's fine on a trusted home
network. Before the dashboard is reachable from anywhere else, put it behind a
sign-in proxy.

[examples/forward-auth/](../examples/forward-auth/README.md) does this with Traefik
and Authelia, and runs on top of the stack with one command. It has two test users
to try it with. To adapt it:

1. **Generate your own secrets** (`example.env`), and replace the users file or
   connect Authelia to your directory. Use `two_factor` for anything internet-facing.
2. **Map groups to roles** with `DASHBOARD_GROUP_ROLES`, for example
   `ops=operator,security=security-operator`. A signed-in user whose groups map to
   no role sees "No access yet" and can't read anything.
3. **Set** `DASHBOARD_AUTH_MODE=trusted-proxy` and `DASHBOARD_TRUSTED_PROXY_SECRET`
   on the dashboard and the API, and `DASHBOARD_AUTH_HEADERS=authelia` on the
   dashboard. Set `DASHBOARD_LOGOUT_URL` to show **Sign out**.
4. **Reach the dashboard only through the proxy:** don't publish its port or the
   API's on a network others can reach.

Other proxies work the same way: `DASHBOARD_AUTH_HEADERS` also accepts `authentik`
and `oauth2-proxy`. Whatever you use, the proxy in front must replace any identity
headers a client sends, and add `x-dashboard-proxy-secret`
([dashboard operations](operations/dashboard.md) lists the headers). Audit entries
then name the signed-in user and record their email.

## Verifying exports

SBOMs, evidence bundles and reports are signed with this instance's own key. The worker creates it on first use
on the `signingkeys` volume; on Kubernetes you create it as a Secret (README). Anyone
with the public key can check that a file came from this Scrutineering and hasn't
changed since. That check is offline, and no Scrutineering code is involved. Next
to each SBOM and evidence download are **signature** and **public key** links (or
`GET /api/dashboard/signing-keys` for every key). The same commands verify both.

```bash
# With openssl
openssl dgst -sha256 -verify scrutineering.pem \
  -signature <(base64 -d sbom.cdx.json.sig) sbom.cdx.json      # "Verified OK"

# With cosign (the signature is in its blob format)
cosign verify-blob --key scrutineering.pem --signature sbom.cdx.json.sig \
  --insecure-ignore-tlog sbom.cdx.json
```

To check a whole compliance export, verify its manifest, then every file against it:

```bash
unzip scrutineering-export-*.zip -d export && cd export
openssl dgst -sha256 -verify keys/<fingerprint>.pem \
  -signature <(base64 -d manifest.json.sig) manifest.json      # "Verified OK"
python3 -c 'import hashlib, json; m = json.load(open("manifest.json")); bad = [f["path"] for f in m["files"]
  if hashlib.sha256(open(f["path"], "rb").read()).hexdigest() != f["sha256"]]; print(bad or "all files match")'
```

The signature says "this instance produced these exact bytes", not that a person
reviewed them. To rotate the key, delete `private.pem` from the volume (or replace the
Secret) and restart the worker. Earlier signatures still verify, because every
public key stays listed. An SBOM made while the key couldn't be used is stored
unsigned, and its page says so.

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
- **No notifications arrive.** Check that `CELERY_QUEUES` includes `notify`, then open
  **Notifications** and choose **Send test**. Each delivery's error is the receiver's
  status code (with Slack's code, such as `no_service`) or the connection error. The
  same rows are in the database:

  ```bash
  docker compose exec postgres psql -U scrutineering -c \
    "select id, event, status, attempts, last_error from notifications order by id desc limit 10"
  ```

To remove all local test images, stop the stack and delete the registry volume:
`docker compose down && docker volume rm scrutineering_registrydata`.
