# Runtime Discovery Scans

Runtime discovery is an opt-in Celery Beat task that uses the existing Docker
or containerd runtime collectors to find running image references and queue
bounded low-priority scans. It is disabled by default because Docker socket or
containerd access grants the worker visibility into the host runtime.

For Docker Compose, enable the worker overlay and configure filters in `.env`:

```dotenv
SCAN_RUNTIME_DISCOVERY_ENABLED=true
SCAN_RUNTIME_INCLUDE_IMAGES=acme/*
SCAN_RUNTIME_EXCLUDE_IMAGES=acme/legacy:*
SCAN_RUNTIME_EXCLUDE_CONTAINERS=scrutineering-*
SCAN_RUNTIME_MAX_IMAGES=100
```

Then start the worker with runtime access:

```bash
export DOCKER_SOCKET_GID="$(stat -c '%g' /var/run/docker.sock)"
docker compose -f docker-compose.yml -f docker-compose.deployment-docker.yml up --build -d celery-worker celery-beat
```

Discovery runs every 15 minutes, deduplicates image references across running
containers, and submits scans through the existing `scan.low` queue. It skips
opaque content digests, filesystem/workspace aliases, reserved `.invalid`
references, images already being scanned, and images scanned within
`SCAN_COOLDOWN_SECONDS`. This prevents a runtime inventory from repeatedly
filling the queue with values that an OCI scanner cannot resolve.

Partial runtime access or a missing CLI produces an empty discovery result;
operators should use `npm run probe:deployment-observation` to validate
deployment evidence access separately. Containerd mode uses
`SCAN_RUNTIME_USE_CONTAINERD` and `SCAN_RUNTIME_CONTAINERD_NAMESPACE` and
requires `ctr` in the worker image. When a local runtime contains application
images that should not be scanned, add their container names or image patterns
to the exclude variables above.

Scanner persistence treats database write failures as `partial` scans. Finding
titles are stored as unrestricted text so long scanner advisories do not cause
otherwise successful scan results to be discarded. Apply migrations before
retrying older partial scans:

```bash
docker compose exec api alembic -c src/db/migrations/alembic.ini upgrade head
```
