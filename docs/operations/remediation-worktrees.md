# Remediation Worktrees

`src.remediation.worktree.RemediationWorktree` provides the isolation boundary
for remediation workers. It verifies the repository root, creates a detached
worktree at `HEAD` with argument-vector Git commands, and force-removes the
temporary worktree on exit, including setup failures.

The manager intentionally does not apply changes, run tests, or merge branches.
Those operations belong in later pipeline stages after parser-aware editing and
validation gates are added.
