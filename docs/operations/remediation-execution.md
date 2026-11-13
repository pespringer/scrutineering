# Remediation Execution Gate

`src.remediation.executor.execute_remediation` is the first executable Phase 2
boundary. It refuses to run without verified evidence, and can verify an
evidence envelope itself before applying caller-supplied
changes only inside a detached worktree, executes validation commands without a
shell, captures bounded command output, and returns `ready` only when every
command passes.

The executor creates a local commit only after all gates pass. The worker can
optionally push that commit to a new branch when `REMEDIATION_PUSH_ENABLED=true`;
it still never merges or opens a pull request. Parser-aware edit adapters and
post-change SBOM/rescan commands should be added before enabling publication.
Guarded `replace_text` edits can build on this boundary. Callers should provide `evidence_envelope`, `evidence_artifact`,
and the provider verifier rather than asserting a boolean in production.

`run_validation_pipeline` defines those publication gates explicitly: install,
test, build, SBOM generation, and post-change rescan. Missing phases or the
first failed command block the run, and later phases are not attempted.

`build_rollback_plan` produces a validated `git revert --no-edit` command for a
published commit. It never executes the rollback; operators must run the plan
inside an isolated worktree and repeat verification gates before publication.
Validated execution can optionally create a local commit artifact with
`commit_message`. The worker's branch publisher refuses existing branch names,
uses a short-lived Git askpass credential, and records the branch in the
`execution_ready` event. It does not merge or open a pull request.

To enable the handoff in a disposable checkout, set `REMEDIATION_PUSH_ENABLED=true`
and provide `GITHUB_TOKEN` with repository Contents **Read and write** and Pull
requests **Read and write** permissions for the target repository. A
fine-grained token must be granted access to that repository; a classic token
needs the `repo` scope. A token that can read administration settings but
cannot write repository contents will authenticate and still fail at `git push`
with HTTP 403. The checkout's `origin` must point at the intended repository; use
`REMEDIATION_GIT_REMOTE` only for an explicitly configured remote. Leave the
flag false for dry-run execution.

To create the GitHub PR automatically after the branch is pushed, also set
`REMEDIATION_PUBLICATION_ENABLED=true`,
`REMEDIATION_PUBLICATION_PROVIDER=github`,
`REMEDIATION_PUBLICATION_REPOSITORY=owner/repository`, and
`REMEDIATION_ALLOWED_REPOSITORIES=owner/repository`. The worker reuses the
existing evidence, allowlist, protected-base, and idempotency gates, then
persists the PR URL and number on the remediation record. It will block rather
than publish if any gate or token is missing.

## Recovery and validation

Remediation lifecycle transitions emit ordered events through the durable event
store. Workers can reconstruct a lifecycle with `RemediationLifecycle.recover`
after restart; missing or out-of-order sequences fail closed. Use
`build_provider_validation_commands()` to create the required install, test,
build, SBOM, and rescan gates for GitHub Actions or GitLab CI and the Node or
Python ecosystem.

Production callers can set `release_evidence=True` on `execute_remediation()`
to force the configured Cosign keyless policy through `verify_release_evidence`;
the executor blocks before creating a worktree when that gate fails.

## Compose test workspace

The Compose worker mounts a disposable Git checkout at `/workspace/repository`
and signed evidence at `/workspace/evidence`. Configure the host directories
with `REMEDIATION_HOST_REPOSITORY_ROOT` and
`REMEDIATION_HOST_EVIDENCE_ROOT`; keep the container-side paths at their
defaults. The checkout must be separate from the main working tree and writable
by the worker's unprivileged `scanner` user. The worker image includes Git,
Node/npm, Syft, Trivy, Grype, and Cosign, but evidence must still be produced and signed by a
trusted release workflow.

### Generate the local test bundle

The repository includes `.github/workflows/remediation-evidence.yml`. Run it
manually from **Actions → Remediation Evidence → Run workflow**, keep `ref` set
to `main`, and wait for the job to finish. It uses GitHub's OIDC identity to
Cosign-sign the evidence artifact and uploads a seven-day bundle.

Download and unpack the workflow artifact into the local evidence mount:

```bash
mkdir -p .local/remediation-evidence
unzip scrutineering-remediation-evidence-*.zip -d .local/remediation-evidence
cp .local/remediation-evidence/evidence-artifact.json .local/remediation-evidence/artifact.json
```

Set the certificate identity in `.env` to the workflow identity used by the
run (for this repository's `main` workflow):

```dotenv
COSIGN_CERTIFICATE_IDENTITY=https://github.com/pespringer/scrutineering/.github/workflows/remediation-evidence.yml@refs/heads/main
COSIGN_OIDC_ISSUER=https://token.actions.githubusercontent.com
```

The worker consumes only `envelope.json` and `artifact.json`; retain the
signature and certificate files for audit evidence. Rebuild the worker after
changing `.env`:

```bash
docker compose up -d --build celery-worker
```

### Source-file scan test mode

Container image scans remain the default. For a disposable checkout, the
Celery scan task also accepts an explicit `fs:/absolute/path` target. Trivy and
Grype then scan the checkout directory, normalize scanner locations to relative
paths such as `requirements.txt`, and persist a local scan record. The public
dashboard image endpoint does not accept filesystem targets.

Example from the worker container:

```bash
docker compose exec celery-worker python -c \
  'from src.scan.tasks import run_scan; print(run_scan.run("fs:/workspace/repository", scanners=["trivy", "grype"]))'
```

Only source paths explicitly returned by a filesystem scanner can become
remediation actions; image findings without a repository coordinate continue to
block safely.

For monorepos, set `REMEDIATION_VALIDATION_WORKING_DIRECTORY` to a safe
relative project directory such as `services/api`. Validation runs there while
the Git worktree and changed-file guard remain rooted at the repository.
