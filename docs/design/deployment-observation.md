# Deployment observation

Status: steps 1–2 built (recording, dashboard) · 2026-11-19 · Phase 6

## Problem

A remediation is `completed` when a complete rescan of the image's **tag** no longer
shows the targeted findings. That proves the fix is in the registry, not that it's
running. After a rebuilt image is pushed, every container started from the old one
keeps running the vulnerable build until someone restarts it. Scrutineering can't
see this today:

- **Runtime discovery** records only that *some* container runs an image name
  (`images.last_seen_running_at`). It doesn't record which containers, or which
  build each one runs.
- **"Completed" overstates what's fixed.** The dashboard says the fix is done
  while the running containers may still have the CVE.
- **There's no "restart these" list,** after a fix or after any rebuild of a tag.

## Scope

**In:**

- **Each discovery run records the running containers** on the host: container
  ID and name, the image reference it was started from, the **image it actually
  runs** (by digest), and when it started.
- **Stale containers:** a container is *stale* when it runs a different build
  than the image's latest scan, i.e. the tag has moved on and the container
  hasn't.
- **Dashboard:**
  - the image page lists its containers, each **current** or **stale**;
  - the Images list shows "2 containers · 1 stale";
  - a completed remediation shows **"Deployed: 1 of 2 containers run the fixed
    build"** until every container does.
- **A notification** (step 3), using the existing channels: a fix whose
  containers are still stale a set time after completion.

**Out:**

- Kubernetes (pods, rollouts), which follows Kubernetes discovery.
- Restarting containers. Scrutineering observes; it never acts on the host. The
  proxy allows no writes, and this keeps it that way.
- Multiple hosts. One stack sees one Docker daemon; several hosts would need an
  agent per host.
- History beyond what's needed: gone containers are kept 30 days, then pruned.

## Design

### What discovery already sees

Through `docker-proxy` (`GET /containers/json`, `GET /containers/{id}/json`, and
`GET /images/{id}/json`, all already allowed), each running container gives:

- `Id` and `Name`;
- `Config.Image`: the reference it was started from (`postgres:16-alpine`);
- `Image`: the image it actually runs, `sha256:…`;
- `State.StartedAt`.

### Matching a container's build to a scan

A scan resolves the tag to a **registry digest** (`Docker-Content-Digest`, the
manifest or index digest). A container's `Image` is the local image ID. Whether
they match depends on Docker's image store:

- **containerd store** (current Docker, as on this host): the image ID *is* the
  manifest or index digest, so it compares directly with the scan's digest.
- **Classic store:** the image ID is the config digest, so it doesn't compare.
  The image's `RepoDigests` (from `GET /images/{id}/json`) list the registry
  digests it was pulled as.

So a container's **running digests** are `{Image} ∪ RepoDigests`. The container
is **current** if those include the digest of the image's latest completed scan,
and **stale** if they don't. If the latest scan has no digest (scanned by tag), the
state is **unknown**, never stale, because Scrutineering won't guess.

### Data: the `deployments` table (migration 0013)

One row per container instance. A recreated container (`docker compose up` after a
pull) has a new ID, so it gets a new row; `docker restart` keeps the ID and updates
`started_at`.

| Column | Notes |
|---|---|
| `container_id` | unique |
| `name`, `image_ref` | as Docker reports them |
| `image_id` | FK to `images`, via the same identity rules as scans |
| `running_digests` | JSON list of `sha256:` digests: the image ID plus those of its RepoDigests |
| `started_at` | from `State.StartedAt` |
| `first_seen_at`, `last_seen_at` | set by discovery runs |
| `gone_at` | set when a run no longer sees it; null while running |

**Current or stale is derived, not stored.** It depends on the image's latest scan,
which changes on its own schedule. Storing it would mean a second status that can
disagree with the first (project rule 3). It's computed when read, from
`running_digests` and the latest completed scan's `image_digest`.

### Discovery changes

`run_discovery` (src/scan/runtime_discovery.py), for each running container of a
scannable image:

1. **Inspect it** (`docker container inspect`, one call for all of them, with a
   format that returns only the five fields above), and look up the RepoDigests of
   each distinct build.
2. **Upsert its `deployments` row:** insert on first sight, otherwise update it and
   `last_seen_at`, and clear `gone_at` if it was set.

Then any running row whose container this run didn't **list** gets `gone_at = now`.
A container that was listed but couldn't be inspected isn't gone. If listing or
inspection fails, nothing is marked gone: "couldn't list" is never "everything
stopped". A daily sweep (03:45, `scan.low`) deletes rows gone for more than 30 days.

On containerd, discovery has no inspect, so nothing is recorded. The run's status
gains `deployments: {recorded, gone}` when containers were recorded.

### Dashboard and API

| Method | Path | Role | Returns |
|---|---|---|---|
| GET | `/images/{id}/deployments` | any | Containers running (or gone within 24 h): `current`, `stale`, `unknown` |
| — | `/images` list | any | gains `containers` and `stale_containers` counts |
| — | `/remediations/{id}` | remediator | gains `deployment`: `{containers, fixed, not_fixed}` once completed |

A container is **running** when discovery listed it within the Running window (30
minutes, as for the Running badge), so a row whose discovery has stopped doesn't
count forever. "Latest scan" is the image's latest completed or partial scan by
start time. `fixed` is null when no fixed build has a digest.

**"Runs the fixed build"** means the container's running digests include the
digest of the scan that **completed** the remediation (the evidence bundle's
`scans.after`), or of a later complete scan in which the targets are still absent.

### Notification (step 3)

A new event, **`remediation.deployment_stale`**, is sent once when a completed
remediation still has stale containers 24 hours after completing. It names the
containers. It goes through the existing outbox and channels, and is listed in
`NOTIFICATION_EVENTS` (on by default).

## Configuration

None new. Observation rides on runtime discovery (`SCAN_RUNTIME_DISCOVERY_ENABLED`)
and the proxy that discovery already uses.

## Security

- **Read-only.** No new proxy permissions: container and image inspection are
  already allowed for discovery. Scrutineering still can't start, stop or exec.
- **What's stored:** container names and image references; never environment
  variables, mounts or commands. `docker inspect` returns all of those, and only
  the four fields above are kept.
- **Who sees it:** container names can reveal what a host runs. The image routes
  need a signed-in user, like the rest of the inventory.

## Testing

- **Unit tests:**
  - running digests from both image stores;
  - current, stale and unknown, including a scan with no digest;
  - upsert, gone and restart (new ID, new row);
  - nothing is marked gone when listing fails;
  - the 30-day prune;
  - the remediation's "N of M run the fixed build";
  - the notification fires once, after 24 h.
- **Golden path:** unchanged. Containers come from discovery, which the golden
  path doesn't run.
- **Live (`make e2e`):** run a container from the fixture image's `:e2e` tag
  before the remediation. After it completes, the remediation shows **0 of 1** and
  the container **stale**. Restart the container from the new tag, run discovery,
  and it shows **1 of 1**.

## Rollout

1. **Record containers:** migration 0013, the discovery changes, gone detection,
   the prune, and tests.
2. **Dashboard:** the image page's containers, the Images list counts, the
   remediation's deployment line, the API, and the e2e scenario.
3. **Notification:** `remediation.deployment_stale`.

Each step keeps the golden path green.

## Decisions

Decided 2026-11-19:

1. **"Deployed" is shown, not a status.** A status would be derived from container
   state that changes outside Scrutineering, and `completed` keeps its meaning: the
   registry is fixed.
2. **The stale-notification delay is 24 hours, fixed.** Rollouts on a home lab are
   manual, so a shorter delay would nag.
3. **Containers of images that can't be scanned aren't recorded.** Without a scan
   there's nothing to compare them with, and discovery already counts them.
