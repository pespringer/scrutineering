# Security hardening: approved sources, a tamper-evident audit log, local ports

Status: built · 2026-11-23 · Phase 6

## Problem

The security review of 2026-11-22 left three gaps that need a design decision:

- **An approved fix can be built from a different source.** Approval is a
  decision about a plan *and* the source it will be built from. The worker reads
  the image's live source when it builds (`worker.py`, `_load`). After approval,
  anyone with `sources.manage`, the proposer included, can change the
  repository, ref, Dockerfile, build arguments or test command. The fix then
  builds code nobody approved, which defeats separation of duties. Publishing is
  safe today because it pushes the verified commit. But it takes the pull
  request's base branch, and the evidence takes the test command, from the live
  source.
- **The audit log can be edited without a trace.** `audit_log` has
  `previous_hash` and `record_hash` columns, and both exports carry them, but
  nothing ever writes them. Someone with database access can change or delete a
  record, and nothing in an export or check shows it.
- **The stack listens on every interface.** Compose publishes the API (8000),
  the dashboard (3001) and the registry (5000) on `0.0.0.0`. The host-access
  overlay does the same for Postgres and Redis. The registry has no
  authentication. In the default `local` sign-in mode, anyone who reaches the
  dashboard is an operator. On a laptop on shared Wi-Fi, that is everyone on the
  network.

## Scope

**In:**

- A copy of the source on each remediation, taken when it's proposed. Every
  later step reads that copy.
- The hash chain, written on every audit record, backfilled for existing records,
  and a way to check it.
- Published ports bound to `127.0.0.1` by default, with a setting to widen them.

**Out:**

- Anchoring the chain outside the database, for example by sending each head to
  a timestamping service. The signed compliance export is the anchor (see Security).
- Authentication on the bundled registry. It stays a local development registry.
- Kubernetes manifests. They don't publish host ports.

## Design

### 1. The source, as approved

- **Migration:** a new nullable JSON column, `remediations.source`, holding
  `repository`, `ref`, `dockerfile_path`, `build_context`, `build_args` and
  `test_command`. The migration fills it for existing remediations from their
  image's current source. Rows whose image has no source stay null.
- **Proposal:** proposing copies the image's source into the column. **Retry**
  copies it again, because a retry returns the fix to approval as a new proposal
  that someone has to approve afresh. Retry is how an operator picks up a
  corrected source.
- **Reads:**
  - the worker builds from `settings_from_record(remediation.source)`, never from
    `image.source`;
  - publishing takes the base branch and the publication target from the copy;
  - the evidence bundle takes the test command from the copy;
  - the publish route's "is it on GitHub" check reads the copy.

  A remediation with no copy fails with "the remediation has no recorded source".
- **Later changes:** changing or removing the image's source doesn't touch
  existing remediations. To stop a fix, cancel it, as today.
- **Dashboard:** the remediation payload gains a `source` field, in the same
  shape as `source_payload` without `updated_by` and `updated_at`. The remediation
  page shows it beside the plan, so an approver sees what they're approving. A
  "Source changed since proposal" notice appears when the image's source no
  longer matches.

### 2. The audit hash chain

- **Hash:** `record_hash = sha256(previous_hash + "\n" + canonical(fields))`.
  - The fields are `timestamp` (ISO 8601, microseconds), `event_type`,
    `entity_type`, `entity_id`, `actor`, `actor_kind` and `detail`.
  - `canonical` is sorted-key, compact JSON, the same as the evidence bundles use.
  - The first record's `previous_hash` is the empty string.
  - `id` is left out because the sequence assigns it. `image_id` is left out
    because deleting an image sets it to null.
- **Writing:**
  - `AuditLogRepository.record` is the only writer. It sets `timestamp` itself
    instead of relying on the server default, so the hashed value is the stored
    one.
  - It takes `pg_advisory_xact_lock` on a fixed key, reads the newest
    `record_hash` by `id`, and computes the new hash.
  - The lock is held until the writing transaction commits, so writers are
    serialised and the chain can't fork. Audit writes are a few per user action;
    the lock is cheap at that rate. SQLite, used in tests, has one writer and
    skips the lock.
- **Backfill:** the migration walks existing records in `id` order and fills both
  columns. It uses its own copy of the hash function, so the migration never
  changes when the app's code does. A test checks that the two copies agree.
- **Checking:**
  - `GET /api/dashboard/audit/verify` (`audit.export`) recomputes the whole
    chain and returns `{"intact": bool, "records": n, "first_broken_id": id|null}`.
  - A Celery Beat task, `verify-audit-chain`, runs the same check daily at 03:50.
    It keeps the result in Redis, the way runtime discovery does. A break is
    logged at error level and appears as a problem in the system status panel.
- **Exports:** `audit.json` and `/audit/export` already carry both columns; they
  are now filled. The operator guide documents the formula, so anyone can check an
  export without Scrutineering.

### 3. Local ports

- **API and dashboard:** published as
  `${PUBLISH_ADDRESS:-127.0.0.1}:${PYTHON_API_PORT:-8000}:8000`, and the same for
  the dashboard.
- **Registry:** published on `${REGISTRY_PUBLISH_ADDRESS:-127.0.0.1}`. A separate
  setting lets a team push images from other machines without also exposing the
  dashboard.
- **Host-access overlay:** `docker-compose.host-access.yml` publishes Postgres
  and Redis, which carry every record and the task queue, for tools on the host.
  Both are bound to `127.0.0.1`, with no setting to widen them.
- **Forward-auth overlay:** unchanged. It already removes the dashboard's
  published port, and Traefik is the entry point.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `PUBLISH_ADDRESS` | `127.0.0.1` | Host address the API and dashboard ports are published on. `0.0.0.0` restores the old behaviour. |
| `REGISTRY_PUBLISH_ADDRESS` | `127.0.0.1` | Host address the bundled registry is published on. |

Both are Compose-only, listed in `src/config.py` as `External` so they appear in
`docs/CONFIGURATION.md`.

## Security

- **Source copy:** an attacker with `sources.manage` can no longer change what an
  approved fix builds. They can still change the image's source before someone
  proposes a fix, but the approver now sees the source next to the plan. The copy
  holds build arguments, which `GET /images/{id}` already shows to the same
  roles, so nothing new is exposed.
- **Hash chain:** it detects any edit, insertion or deletion *inside* the chain.
  It doesn't stop someone with database write access from rewriting every record
  after a point and recomputing the hashes. What catches that is an earlier
  signed compliance export: its manifest is signed, `audit.json` is in the
  manifest, and the newest `record_hash` in a kept export must still be in the
  live chain. Keep exports somewhere the database's owners can't write.
- **Ports:** after the change, a fresh stack is reachable only from the host.
  Widening it is a deliberate setting.

## Testing

- **Source copy:**
  - proposing stores the copy;
  - changing the source after approval doesn't change what the worker clones or
    builds;
  - retry takes a fresh copy;
  - publishing uses the copied ref;
  - the migration backfills.
- **Hash chain:**
  - records chain;
  - editing a record's detail, deleting one, or reordering two breaks
    verification at the right `id`;
  - setting an image's audit `image_id` to null doesn't break it;
  - the migration's hash function matches the app's.
- **Ports:** `validate-deployment-config` checks that every published port in
  the Compose files has a host address.
- **Golden path:** `make e2e` passes unchanged. It reaches the stack on
  `localhost`. It also calls `/audit/verify` at the end and expects `intact`.

## Rollout

One PR after this note merges:

- migration `0018`;
- the source copy;
- the hash chain and its check;
- the port bindings;
- the operator guide's audit section and `docs/CONFIGURATION.md`.

Dependency upgrades are a separate PR.

## Decisions

1. A "source changed since proposal" notice only warns. The approver approves what's
   shown, which is the copy.
2. Two settings: one for the API and dashboard, one for the registry. Sharing the
   registry is common, and opening a `local`-mode dashboard shouldn't be the side
   effect.
