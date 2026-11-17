# Remediation execution

A remediation fixes selected findings on one image: it patches the image's
source, builds a candidate image, and scans the candidate to prove the targeted
findings are gone. The server decides every outcome from what it checked out,
built and scanned itself.

## Prerequisites

1. **A connected source.** On the image page, use **Source → Connect source** (or
   `PUT /api/dashboard/images/{id}/source`). The repository is either an
   `https://` git URL (a private github.com repository is cloned with
   `GITHUB_TOKEN`), or a folder (a git repository) under the worker's sources
   directory. Locally that is `./.local/remediation-sources`
   (`REMEDIATION_HOST_SOURCES`), mounted read-only at `/workspace/sources`.
   Also set the ref, the Dockerfile path and the build context.
2. **Execution enabled.** Set `REMEDIATION_EXECUTION_ENABLED=true` for the API.
3. **The `buildkitd` service running.** `make up` starts it. It is rootless
   BuildKit: the worker reaches it at `BUILDKIT_HOST` (`tcp://buildkitd:1234`)
   and never needs the Docker socket. The host kernel must allow unprivileged
   user namespaces (`/proc/sys/user/max_user_namespaces` greater than 0).

## How a fix is chosen

The preview (`POST /api/dashboard/remediations/preview`) groups the selected
findings into actions by package type:

| Strategy | Findings | What execution does |
|---|---|---|
| `dependency_update` | npm or pip packages with a fixed version | npm: `npm install pkg@version --save-exact --package-lock-only --ignore-scripts` for a direct dependency, or an `overrides` entry for a transitive one. pip: rewrite `pkg==` pins in `requirements*.txt`. |
| `os_package_upgrade` | apk, deb or rpm packages with a fixed version | Add `RUN apk add --upgrade …` (or the apt/dnf equivalent) right after the final stage's `FROM`. |
| `base_image_bump` | Runtime binaries that ship in the base image (for example `node`) | Rewrite the final stage's `FROM` to the newest tag of the same line, found through the registry tags API (`18.12-alpine` → `18.20-alpine`). |
| manual | No fixed version, or an unsupported ecosystem | Nothing; the preview shows why. |

Package-manager commands run without the worker's credentials in their
environment, and npm never runs package scripts.

## What execution does

`POST /remediations/{id}/execute` moves an approved remediation to `building`
and queues it on `remediation.normal`. The worker then:

1. Clones the source at its ref into a temporary directory. The source itself is
   never modified.
2. Applies each action and records the resulting `git diff` as the remediation's
   `patch`, and the commit it patched as `source_commit`.
3. Builds the patched source with BuildKit and pushes the result to the local
   registry as `<repository>:scrutineering-candidate-<id>`. This is recorded as
   `candidate_image` and `candidate_digest`.
4. Moves to `verifying` and scans the candidate by digest with the same scanners
   and settings as any scan. Nothing about the candidate is saved to the
   inventory.
5. Decides the outcome:
   - If any targeted `vuln_key` is still present, the remediation is `failed`.
   - If it introduced critical or high findings the image did not already have,
     it is `needs_acceptance` (decision D6). A security operator accepts it
     (→ `ready`) or cancels it.
   - Otherwise it is `ready`.

   The comparison is stored as `verification`.

Every failure leaves the remediation `failed` with the reason in
`error_message`: no source, clone failure, the package not being in the source,
a build error (the last part of the build log is kept), or an incomplete
candidate scan. **Retry** returns it to `proposed`, so it is approved again.

A `ready` remediation becomes `completed` when a complete rescan of the image no
longer shows any targeted finding. That happens once the image is rebuilt from
the patched source and scanned again. To get the patch into the source, apply it
yourself or, for a github.com source, open a pull request with it (see
[GitHub publication](github-publication.md)), which makes it `published`.

## Remediation statuses

A remediation has one `status`, changed only through the transitions in
`src/remediation/state_machine.py`:

`proposed` → `approved` → `building` → `verifying` → `ready` → (`published`) → `completed`

- `needs_acceptance` follows `verifying` when the candidate adds new critical or
  high findings.
- `published` means a GitHub pull request with the patch is open. It fails if the
  pull request is closed unmerged, or if the image is rebuilt (a new digest) and
  still has a targeted finding.
- `failed` records the reason in `error_message`; retry returns it to `proposed`.
- `cancelled` releases the remediation's findings so they can be proposed again.
- `completed` is set by the server when a complete rescan of the image no longer
  shows any targeted `vuln_key`, at any version.

Creating a remediation reserves its findings. Requests that do not match the
current status return 409 with the allowed statuses. Events record history and
are never read to decide current state.

## Trying it locally

`make e2e` pushes the fixture image, connects its source (a git copy of
`fixtures/images/vulnerable-node` under `.local/remediation-sources`), fixes
lodash, and checks that the candidate is verified and the remediation completes
after a rescan.
