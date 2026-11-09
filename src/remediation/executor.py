"""Fail-closed remediation execution inside an isolated Git worktree."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Sequence

from .worktree import RemediationWorktree


@dataclass
class RemediationExecution:
    status: str
    worktree: str | None = None
    commands: list[dict[str, object]] = field(default_factory=list)
    changed_files: list[str] = field(default_factory=list)
    error: str | None = None


def execute_remediation(
    repository: str | Path,
    changes: Sequence[object],
    apply_change: Callable[[Path, object], None],
    validation_commands: Sequence[Sequence[str]],
    *,
    evidence_verified: bool,
    base_dir: str | Path | None = None,
    timeout_seconds: int = 600,
) -> RemediationExecution:
    """Apply supplied changes and run all validation commands in a worktree."""
    if not evidence_verified:
        return RemediationExecution(status="blocked", error="verified evidence is required")
    if timeout_seconds < 1:
        raise ValueError("timeout_seconds must be positive")

    try:
        with RemediationWorktree(repository, base_dir) as worktree:
            for change in changes:
                apply_change(worktree, change)
            command_results = []
            for command in validation_commands:
                if not command:
                    return RemediationExecution(status="failed", worktree=str(worktree), error="empty validation command")
                result = subprocess.run(
                    list(command), cwd=worktree, check=False, capture_output=True,
                    text=True, timeout=timeout_seconds,
                )
                command_results.append({
                    "command": list(command), "returncode": result.returncode,
                    "stdout": result.stdout[-2000:], "stderr": result.stderr[-2000:],
                })
                if result.returncode != 0:
                    return RemediationExecution(status="failed", worktree=str(worktree), commands=command_results, error=f"validation failed: {command[0]}")
            diff = subprocess.run(
                ["git", "diff", "--name-only"], cwd=worktree, check=True,
                capture_output=True, text=True,
            )
            changed_files = [line for line in diff.stdout.splitlines() if line]
            return RemediationExecution(status="ready", worktree=str(worktree), commands=command_results, changed_files=changed_files)
    except subprocess.TimeoutExpired as exc:
        return RemediationExecution(status="failed", error=f"validation timed out: {exc.cmd}")
    except Exception as exc:
        return RemediationExecution(status="failed", error=str(exc))
