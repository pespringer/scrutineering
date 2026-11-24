# Runtime discovery on by default

Status: built · 2026-11-18 · Phase 6

## Problem

Scrutineering only scans images someone pushes or names. The images actually
running on the host are the ones that matter, and nothing finds them unless
discovery is turned on. Turning it on today doesn't work, and wouldn't be safe
if it did:

- **It can't see anything.** The worker image has the `docker` CLI, but the
  default Compose stack gives the worker no Docker daemon. `docker ps` fails,
  `run_cli` treats the failure as "no containers", and every run reports
  `discovered: 0` without a log line.
- **The only way to make it see is to hand over the host.** The opt-in overlay,
  `docker-compose.deployment-docker.yml`, mounts `/var/run/docker.sock` into the
  worker. That socket is root on the host: anything holding it can start a
  privileged container. The worker is also the process that clones sources, runs
  package managers and drives builds, so it's the last process that should have it.
- **It would flood the queue.** Discovery calls `queue_scan` directly every 15
  minutes for every running image, up to 100. That skips both the cooldown
  (`SCAN_COOLDOWN_SECONDS`) and the check for a scan already pending or running,
  which scheduled rescans respect. The same unchanged images would be rescanned
  96 times a day.
- **Some running images can't be scanned.** `docker ps` reports an image ID when
  a tag was removed, and a name such as `myapp:dev` for an image built on the host.
  The scanners pull from a registry and have no daemon, so both fail every time
  they're queued.
- **Nothing records what's running.** After a scan, an image that is running looks
  the same as one somebody scanned once a month ago.

## Scope

**In:**

- Discovery that works in the default Compose stack, through a socket proxy that
  allows read-only listing of containers and images. The worker never gets the
  socket.
- Discovery queues only images that need it: new to Scrutineering, or not scanned
  within the cooldown, and with no scan already pending or running.
- Skip what can't be scanned: image IDs, and images built locally (no registry
  digest). Count them instead.
- `images.last_seen_running_at`, set by each discovery run, plus a **Running**
  badge and filter on the Images page.
- Discovery's last result in the system status panel, including a failure such
  as "can't reach Docker".
- `SCAN_RUNTIME_DISCOVERY_ENABLED` defaults to `true`.
- Removing `docker-compose.deployment-docker.yml`, the raw-socket overlay.

**Out:**

- Kubernetes discovery (see Decisions). The existing containerd collector
  stays as it is, off by default.
- Which containers run an image, and where. That is the "deployment observation"
  Phase 6 item. This note only records that an image was running.
- Scanning images that exist only on the host. That would need the scanners to
  read from the daemon, which is a much larger grant.

## Design

### Reaching Docker without the socket

A new Compose service, **`docker-proxy`**, runs
[docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy) (pinned):

- It mounts the host socket **read-only**, on a host path set by `DOCKER_SOCKET`
  (default `/var/run/docker.sock`). The variable is there for rootless Docker,
  whose socket lives elsewhere.
- It allows only `GET` on `/containers` and `/images`, plus the version and ping
  endpoints. It refuses every `POST`, `DELETE`, exec, build and volume call.
- It sits on a new internal network, **`discovery`**, with no internet access.
  Only the worker joins that network; the API, the dashboard and BuildKit can't
  reach the proxy.
- The worker sets `DOCKER_HOST=tcp://docker-proxy:2375`, so the existing `docker`
  CLI collector works unchanged.

On a host with no Docker socket at that path, the proxy's checks fail and
discovery reports the error. Everything else in the stack keeps working.

### What a discovery run does

`discover_runtime_scans` runs every 15 minutes, as now:

1. **List containers** with `docker ps`, as now, and apply the existing
   include/exclude filters. Containers labelled `scrutineering.scan=false` are
   always skipped.
2. **Inspect each distinct image** (`docker image inspect`) and sort it:
   - **scannable**: it has a `RepoDigests` entry, so it was pulled from a
     registry. Discovery records the name it runs under; each scan resolves
     the digest itself, as every scan does;
   - **local-only**: no registry digest. It's counted and skipped;
   - **ID only**: the container shows only an image ID. It's counted and skipped.

   With containerd there is no registry-digest check: named images are kept, and
   only bare IDs are skipped.

   **As built,** `RepoDigests` alone doesn't separate local builds. Docker's
   containerd image store, the default in current Docker releases, gives a locally
   built image a digest too. So an image with a digest is also checked against its
   registry, with the worker's own credentials, the way every scan resolves its
   digest. If the registry says it doesn't exist or refuses access, the image is
   local-only. If the registry can't be reached, the image is kept and the scan
   decides. Images that already have a successful scan skip this check, so a
   steady state makes no extra registry calls.
3. **Record what's running.** Each scannable image gets an `images` row if it has
   none, and `last_seen_running_at = now`.
4. **Queue only what needs it.** Discovery uses the same rule as scheduled rescans
   (`ScanCooldown` and the active-scan check), so it queues an image only if it
   has never been scanned, or was last scanned before the cooldown, and has no
   pending or running scan. In steady state, discovery scans *new* running images
   within 15 minutes, and the 6-hourly schedule keeps them current.
5. **Report.** The result (counts, or the error) goes into Redis under one key
   with a one-hour expiry, and into the worker log. The system status panel reads
   it, for example: "Discovery: 7 running images, 1 local-only skipped, 3 minutes
   ago", or "Discovery: can't reach Docker (docker-proxy)". If the key has
   expired, the panel says discovery hasn't reported. There is no new table. This
   is status, not history.

`run_cli` keeps returning `None` for a missing binary, but discovery now tells
"couldn't list" apart from "nothing running", and reports the first.

### Running images in the dashboard

- **Images:** a **Running** badge on images with `last_seen_running_at` within
  the last two discovery intervals (30 minutes), and a filter for them.
- **Overview:** the open-finding counts stay as they are. Adding a "running only"
  view of the posture is a later step.

### Migration 0009

Adds `images.last_seen_running_at` (nullable `DateTime`, indexed). Existing
images keep `NULL`, meaning not seen running.

## Configuration

| Variable | Default | Read by | Notes |
|---|---|---|---|
| `SCAN_RUNTIME_DISCOVERY_ENABLED` | **`true`** (was `false`) | worker | Off switch. Reports an error without Docker. |
| `DOCKER_SOCKET` | `/var/run/docker.sock` | Compose | Host path of the socket the proxy mounts read-only. |
| `DOCKER_HOST` | `tcp://docker-proxy:2375` in Compose | worker (`docker` CLI) | Set by Compose; an external variable. |

The existing `SCAN_RUNTIME_*` filters, limits and containerd settings are
unchanged. `SCAN_RUNTIME_MAX_IMAGES` now caps the scans *queued* per run, not the
images recorded as running.

## Security

- **What the worker can do through the proxy:** list and inspect containers and
  images. That includes reading other containers' configuration, environment
  variables among them, because Docker's API doesn't separate listing from
  inspecting. It can't start, stop, exec into or create anything, mount host
  paths, or reach the daemon's other endpoints. Today the opt-in overlay gives
  full root on the host; the proxy replaces that.
- **The remaining exposure, environment variables,** is the main trade-off.
  Anyone who takes over the worker can already read its own `GITHUB_TOKEN` and
  registry credentials. With discovery on, they could also read secrets that
  other containers on the host keep in environment variables (decision 1).
- **Network reach:** the proxy is on an internal network with only the worker.
  It has no published port and no internet access.
- **The proxy itself** runs read-only, without new privileges, with every
  capability dropped. It is the only part of the stack that touches the host
  socket.
- **On by default** means a fresh `make up` lists the host's containers. The
  operator guide says so, with the off switch, in the quick start.

## Testing

- **Unit tests:**
  - the image classification: scannable, local-only, ID only;
  - the cooldown and active-scan rules applied to discovery: a second run with
    nothing new queues nothing;
  - the opt-out label;
  - `last_seen_running_at` updates and new image rows;
  - an unreachable Docker is reported as an error, not as zero;
  - the status payload.
- **Golden path:** unchanged. Discovery is a separate entry point to the same
  scan path.
- **Live,** on the Compose stack:
  - the proxy refuses `POST /containers/create` and `exec`;
  - a run finds the stack's own running images, queues them once, and queues
    nothing on the second run;
  - a locally built image is counted as local-only;
  - Running shows on the Images page;
  - stopping the proxy shows "can't reach Docker" in the status panel.

## Rollout

1. **Discovery that's safe to leave on** (built; default still off):
   - classification and the skips;
   - cooldown and active-scan checks;
   - `last_seen_running_at` and migration 0009;
   - the status in Redis and the system status panel;
   - tests and docs.
2. **On by default in Compose** (built):
   - the `docker-proxy` service and the `discovery` network;
   - `DOCKER_HOST` for the worker;
   - remove the raw-socket overlay;
   - `SCAN_RUNTIME_DISCOVERY_ENABLED=true`;
   - the Running badge and filter;
   - the operator guide and quick start;
   - the live checks.

Each step keeps the golden path green.

## Decisions

These were open questions on the proposal; all three were decided as recommended.

1. **Container environment variables:** accepted. Through the proxy, the worker
   can read other containers' configuration, including their environment
   variables. That's a large step down from today's opt-in, which is root on the
   host. The operator guide states the trade-off next to the off switch. A
   purpose-built agent that returns only image names and digests remains the
   fallback if that changes.
2. **Kubernetes discovery:** a later step, after this ships and the manifests
   have been deployed.
3. **Local-only images:** counted in the discovery status, not listed.
