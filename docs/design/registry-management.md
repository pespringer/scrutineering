# Registry management

Status: proposed · 2026-11-24 · Phase 6

## Problem

The stack ships a registry, and every remediation pushes to it, but the dashboard
can only list its tags. An operator can't see what an image contains or how much
it stores, can't delete one, and can't reclaim its disk space short of deleting
the whole registry volume. What the catalog does show is partly wrong:

- **Size** is the manifest's `Content-Length`: about 2 KB for a 53 MB image.
- **Multi-platform tags fail.** The catalog's `Accept` header leaves out OCI
  indexes, so the registry answers 404 and the digest is "unavailable".
- **Wrong scan results.** A tag with no tracked image falls back to a lookup by
  bare name, so `registry:5000/team/app:1.0` can show the findings of Docker Hub's
  `team/app:1.0`.
- **Candidates are never removed.** Each remediation that builds leaves a
  `scrutineering-candidate-<id>` tag. On the development stack they are 40 of 46
  tags.

## Scope

**In:**

- A correct catalog, grouped by repository, and a details view for each tag.
- Deleting tags from the dashboard, one or several at a time.
- Daily removal of candidates 30 days after their remediation ends.
- `make registry-gc`, which frees the disk space of what was deleted.

**Out:**

- Any registry but the bundled one (`LOCAL_REGISTRY_HOST`). Scrutineering only
  ever pulls from the others.
- Push and pull times. The registry doesn't record them. Registry notifications
  could supply push times later, for new pushes only.
- Retagging, copying, uploading, and retention rules for an operator's own tags.
- A garbage-collection button. It would need control of the registry container.
- Authentication on the registry (see Security).

## Design

Reading and deleting live in a new `src/scan/registry_catalog.py`, next to
`src/scan/registry.py`. The registry routes move from `src/api/routes/images.py`,
which is near the size limit, to `src/api/routes/registry.py`.

### 1. Catalog and details

`GET /registry/inventory` keeps its path and permission (`registry.view`), and:

- accepts OCI indexes, and follows `Link` pagination for repositories and tags;
- matches a tag to a tracked image by its full name, host included, with no
  fallback;
- returns, for each tag, its compressed size, platforms, the other tags with the
  same digest, and whether it's a candidate (with its remediation's ID and status);
- returns stored bytes for each repository and in total, counting each blob once;
- leaves out repositories with no tags. The registry keeps listing them after
  their last tag is deleted.

For an index, the size is listed per platform. Entries with the platform
`unknown/unknown` are build attestations: counted, but not shown as platforms.

`GET /registry/tags/detail?repository=&tag=` adds the layers, the build date,
labels, entrypoint, command, exposed ports, user and build history, read from the
image's config blob. Environment values aren't returned, because they often
hold secrets.

A manifest never changes for a given digest, so parsed manifests are cached in
Redis by digest for 7 days. Repeat loads cost one `HEAD` per tag. Manifests and
config blobs over 4 MB are reported as unreadable rather than parsed.

### 2. Deleting tags

This needs `registry:3`. Tested against both versions on 2026-11-24:

| | `registry:2` (2.8.3) | `registry:3` (3.1.2) |
|---|---|---|
| `DELETE` by tag | 400 | 202, removes that tag only |
| `DELETE` by digest | 202, removes every tag with that digest | the same |
| Reads a volume written by `registry:2` | – | yes |

Deleting by digest isn't safe here: on the development stack 32 candidates share
one digest. Scrutineering therefore deletes **by tag only**. On `registry:2` the
request fails with `registry_delete_unsupported`; nothing falls back to digests.

`POST /registry/tags/delete` takes up to 100 `{repository, tag, digest}` items,
where `digest` is the one the operator saw. It's a precondition and not a fact:
the server resolves the tag itself, and answers `tag_changed` if they differ.
Names are checked against the OCI grammar, and each item has its own result.

Each item is refused, with a reason the dashboard shows, when:

- **a remediation needs it:** the tag is the candidate of a remediation that isn't
  `completed`, `failed` or `cancelled`, or the tag's image has such a remediation
  (it completes only when that tag is rescanned);
- **a scan is using it:** its image has a pending or running scan;
- **it's running:** a container that isn't gone names the tag; or runs its
  digest and no other tag keeps it; or runtime discovery saw the image within its
  running window (the only signal on containerd).

The running check compares names under both `LOCAL_REGISTRY_HOST` and
`LOCAL_REGISTRY_PUBLIC_HOST`, since the same image is `registry:5000/...` to the
services and `localhost:5000/...` to Docker. Digests include the index, its
platform manifests and their configs, because Docker may report any of them.

There is no override. Stop the container or cancel the remediation first.

For each item, in one transaction: lock the remediation rows, check, `DELETE`,
then archive the tracked image (`active = false`) and record the audit entry.
Archiving stops scheduled scans. Scans, findings, SBOMs and evidence stay, and
scanning the name again brings the image back. The audit entry comes last so that
its chain lock isn't held during the registry call. If the commit fails after the
`DELETE`, that is logged at error level, and the tag shows as gone on the next load.

The audit entry is a `config_changed` event with the action `delete_registry_tag`.
Its entity ID is the digest, since a full reference can exceed the column's 128
characters; the reference is in the detail. No migration is needed.

### 3. Candidate cleanup

A daily task, `prune-candidates`, deletes a candidate when all of these hold:

- its remediation is `completed`, `failed` or `cancelled` **now**, and its
  `completed_at` is over 30 days old. The status is checked because a retry
  leaves `completed_at` set;
- the tag is the one that remediation would push (`candidate_reference`);
- the tag's digest equals the remediation's recorded `candidate_digest`;
- none of the refusals above applies.

It uses the same code and row lock as a manual delete, so a retry can't start
halfway through. It records a `candidate_deleted` event on the remediation. A
retry builds its candidate again, so a failed one isn't needed for that.

Anything that doesn't match is left for an operator, and marked in the catalog.
That covers candidates from an earlier database, whose IDs may have been reused,
and ones pushed just as their remediation was cancelled, which recorded no digest.

The 30 days are a constant, like the retention of deployments and notifications.

### 4. Freeing disk space

Deleting a tag frees nothing by itself. In the same tests, `garbage-collect` alone
kept the untagged manifests and their layers. `--delete-untagged` freed them, and
kept multi-platform images and images with another tag intact.

`make registry-gc` runs a script that:

1. runs a preflight in the API container, and stops if a remediation is building
   or verifying, or a scan is pending or running;
2. stops if a running container uses a digest that no tag keeps, and lists them.
   Collection would remove that build from the registry;
3. stops the registry, which also clears its in-memory blob cache;
4. runs `registry garbage-collect --delete-untagged` in a one-off container on
   the same volume;
5. starts the registry again, whatever happened, and prints the space freed.

Pushes during collection can corrupt images. Stopping the registry rules them out,
at the cost of a short outage. Anything still pulled by digest but not tagged
is removed, and the operator guide says so.

### 5. The `registry:3` image

- Pinned to an exact 3.x release at least 14 days old, in Compose and `k8s/`.
- Its default config **turns deletion on**, so the upgrade is part of step 2,
  not step 1. Until then Compose stays on `registry:2`.
- It also serves debug and metrics on `:5001` and logs at debug level. Compose and
  `k8s/` bind that port to loopback and set the log level to `info`.
- The Compose health check still works: the image has `wget`.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `REGISTRY_STORAGE_DELETE_ENABLED` | `true` | Lets the registry delete images. |

The variable is already used in `k8s/`; Compose now passes it too. With `false`, the
registry refuses deletes and the dashboard says so.

One new Make target, `registry-gc`. No new service or top-level module.

## Security

- **Permission:** a new action, `registry.delete`, for `security-operator` (and
  `admin`). `images.archive` stays with operators, because archiving can be undone.
- **Deletion outside the dashboard:** the registry has no authentication, so with
  deletion on, anything that reaches port 5000 can delete images and skip every
  check above. The same caller can already overwrite any tag, so what's new is
  losing images rather than trusting them. The port is on `127.0.0.1` by default.
  With `REGISTRY_PUBLISH_ADDRESS=0.0.0.0`, set the variable above to `false`; the
  guide and `docs/CONFIGURATION.md` say so.
- **Build steps:** buildkitd shares the registry's network, so a `RUN` step in a
  remediation's source should be assumed able to reach it. An approver already
  decides which sources build.
- **Image metadata is untrusted.** Labels and history are written by whoever
  built the image. They are size-limited and rendered as text.
- **Requests:** the API only calls the configured registry. Repository and tag
  names are validated before they're put in a URL.

## Testing

Unit tests use a fake registry and cover:

- **Catalog:** an index, attestation entries, shared blobs counted once, shared
  digests, pagination, empty repositories, an oversized blob, and a Docker Hub
  image with the same name.
- **Deletion:** each refusal, both host names, a changed digest, `registry:2`'s
  400, deletion turned off (405), the role check, the audit entry, and a mix of
  accepted and refused items.
- **Cleanup:** the 30-day boundary, a retried remediation, a digest that differs,
  a missing digest, and an ID that doesn't exist.
- **Manifests:** `validate-deployment-config` and `tests/test_k8s_manifests.py`
  check the pinned image and the debug address. No cluster is available, so the
  Kubernetes change isn't tested live.

Golden path (`make e2e`): the catalog shows the candidate with a real size;
deleting it while its remediation is `ready` is refused; and deleting one of two
test tags with the same digest leaves the other pullable.

`make registry-gc` is run by hand on a Compose stack before its PR merges: push,
delete, collect, then pull a kept multi-platform tag and push the deleted image
again.

## Rollout

One PR per step, in order:

1. **Catalog:** the three fixes, sizes, details and grouping. Stays on
   `registry:2`.
2. **Deletion:** `registry:3`, `registry.delete`, the route and the dashboard.
3. **Candidate cleanup.**
4. **`make registry-gc`** and the operator guide's section on disk space.

Back up the registry volume before step 2. Going back to `registry:2` on a volume
that `registry:3` has written to is untested.

## Decisions

1. **Who can delete:** `security-operator` and `admin`. Archiving an image can be
   undone and deleting a tag can't, so `operator` keeps only the first.
2. **Deletion is on by default,** since the registry's port is local by default.
   Turning it off also stops candidate cleanup.
3. **Candidates are kept for 30 days** after their remediation ends.
