# Pinned Python dependencies

Status: built · 2026-11-24 · Phase 6

## Problem

`requirements.txt` names 18 packages and pins one (`cryptography`). Every image
build, CI run and `make test` installs whatever is newest on PyPI at that moment,
along with about 40 packages they pull in, none of them pinned. So two builds of
the same commit can differ. A breaking release lands without anyone choosing
it. A compromised release reaches the API and worker images, which hold the
signing key, the GitHub token and the Docker socket proxy, as soon as it's
published. Nothing checks that a downloaded file is the one we tested.

## Scope

**In:**

- A lock file with every package, direct and indirect, at an exact version with
  its sha256 hashes.
- One command to refresh it, which only takes releases at least 14 days old.
- A repository check that the lock covers every direct dependency.

**Out:**

- Splitting test-only packages (`pytest`, `pytest-cov`) out of the images. It's
  worth doing, but it changes what the images contain, so it's a separate change.
- Pinning base images (`python:3.13-slim`, `node:22-alpine`) by digest.
- Automatic update PRs (Dependabot or Renovate). Refreshing stays a deliberate
  `make lock` and a reviewed diff.
- The dashboard. `package-lock.json` already pins npm packages with integrity
  hashes.

## Design

- **`requirements.in`** (new) holds the direct dependencies, as `requirements.txt`
  does now. People edit this file.
- **`requirements.txt`** becomes generated. It's the output of
  `uv pip compile requirements.in --universal --generate-hashes --python-version 3.13
  --exclude-newer <date>`, with `<date>` 14 days before the run. The command is
  written at the top of the file, so anyone can see which cutoff produced it and
  rerun it.
  - `--universal` resolves for every platform at once. The lock then works on Linux
    images, on CI, and on a developer's Mac.
  - With hashes in the file, `pip install -r requirements.txt` turns on pip's
    hash-checking mode by itself. A file that doesn't match its hash fails the
    install, and so does a package missing from the lock.
- **Every consumer keeps reading `requirements.txt`:** `Dockerfile.api`,
  `Dockerfile.worker`, CI and the Makefile's `uv run --with-requirements`. None
  of them change.
- **`make lock`** (new Make target) regenerates `requirements.txt`. It works out
  the cutoff date itself, using GNU or BSD `date`.
- **Check:** `scripts/check-python-lock.mjs`, run by `make check`, fails when a
  package in `requirements.in` has no `==` pin in `requirements.txt`, or a pin has
  no hash. It reads only the two files, so it needs no network. It catches a
  dependency added to `requirements.in` without running `make lock`.
- **Upgrading one package:** edit `requirements.in` if needed and run `make lock`.
  The lock diff shows every version that moved.

## Configuration

None. There are no new settings.

## Security

- **Reproducible builds:** a build installs exactly the files the lock names, or
  fails.
- **Release age:** a release must be at least 14 days old before it can enter the
  lock. Most compromised releases are found and pulled within days.
- **Review:** a refresh is a diff a reviewer can read. Nothing upgrades between
  refreshes.
- **What it doesn't stop:** a release that is malicious and stays undetected for
  14 days. The lock makes that a deliberate, reviewable step rather than a silent
  one.

## Testing

- `scripts/tests/check-python-lock.test.mjs` covers the check: a missing pin, a
  pin without hashes, and a valid lock.
- `make test`, `make up` and `make e2e` install from the lock, and pass.
- CI's `pip install -r requirements.txt` runs in hash-checking mode.

## Rollout

1. This note.
2. One PR: `requirements.in`, the generated `requirements.txt`, `make lock`, the
   check and its test, and the docs (`AGENTS.md`, the README's development
   section).
3. The Python 3.13 image change follows, and regenerates the lock for 3.13.

## Decisions

These were open questions on the proposal; both were decided as recommended.

1. **Release age:** 14 days, the same rule the dependency upgrades used. A shorter
   wait gets fixes sooner, but gives less time for a bad release to be found.
2. **Test packages:** `pytest` and `pytest-cov` stay in the images for now.
   Splitting them out would make the images smaller, but it's a separate change.
