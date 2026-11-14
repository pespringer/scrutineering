# Practical Milestone Acceptance Run

This run validates the home-lab path from a vulnerable source coordinate to a
guarded, clean rescan. It uses the disposable checkout mounted at
`/workspace/repository` and signed evidence mounted at `/workspace/evidence`.
It never changes the main Scrutineering checkout, pushes a branch, or publishes
a provider PR.

## Prerequisites

- Compose services are healthy: `docker compose ps`.
- The worker is started with the Docker overlay when runtime discovery is
  enabled; confirm `/var/run/docker.sock` exists in `celery-worker`.
- `.local/remediation-repo/source-fixture` is a disposable Git checkout with a
  deliberately vulnerable dependency.
- `.local/remediation-evidence/envelope.json` and `artifact.json` contain the
  signed release evidence accepted by the worker.

## Acceptance sequence

1. Run `npm run smoke:milestone1` to queue two real image scans and verify
   durable findings and stable repeat results.
2. Run runtime discovery from the worker. It must report discovered and queued
   images, for example:

   ```bash
   docker compose exec celery-worker python -c \
     'from src.scan.tasks import discover_runtime_scans; print(discover_runtime_scans.run())'
   ```

3. Scan the source fixture with both scanners through Celery and confirm a
   completed persisted scan with repository file coordinates.
4. Submit a remediation only after review and approval. The worker must verify
   signed evidence, apply exact-match edits in a detached worktree, and run
   install, test, build, SBOM, and rescan gates in that order.
5. Accept only a `ready` result with a commit identity and a zero-finding
   rescan for the targeted fixture. A failed gate must leave the source
   checkout unchanged.

## Evidence recorded

The November 14, 2026 run completed the image smoke test, discovered seven
Compose images, scanned the fixture to eight persisted findings, and produced
guarded commit `59750abdf0d306adfaf47f770f944b7220942826`. The final fixture
rescan passed all five gates with zero vulnerabilities. The first attempted
partial fix failed closed at the rescan gate, demonstrating that unresolved
findings cannot produce a ready artifact.

## Known limitations

Provider PR publication, merge callbacks, deployed-digest observation, and
external alert delivery remain separate infrastructure-gated checks. They are
disabled unless explicitly configured and must not be inferred from this local
acceptance run.
