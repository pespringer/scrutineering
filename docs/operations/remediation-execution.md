# Remediation Execution Gate

`src.remediation.executor.execute_remediation` is the first executable Phase 2
boundary. It refuses to run without verified evidence, and can verify an
evidence envelope itself before applying caller-supplied
changes only inside a detached worktree, executes validation commands without a
shell, captures bounded command output, and returns `ready` only when every
command passes.

The executor never commits, pushes, or opens a pull request. Parser-aware edit
adapters and post-change SBOM/rescan commands should be added before enabling
publication. Guarded `replace_text` edits can build on this boundary. Callers should provide `evidence_envelope`, `evidence_artifact`,
and the provider verifier rather than asserting a boolean in production.

`run_validation_pipeline` defines those publication gates explicitly: install,
test, build, SBOM generation, and post-change rescan. Missing phases or the
first failed command block the run, and later phases are not attempted.

`build_rollback_plan` produces a validated `git revert --no-edit` command for a
published commit. It never executes the rollback; operators must run the plan
inside an isolated worktree and repeat verification gates before publication.
