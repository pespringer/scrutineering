"""Fail-closed remediation execution inside an isolated Git worktree."""

from __future__ import annotations

import subprocess
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Sequence

from .worktree import RemediationWorktree
from .approval import verify_approval
from src.scan.evidence import EvidenceVerificationError, verify_evidence, verify_release_evidence
from src.platform.controls import bounded_output, classify_validation_failure, guard_changed_files


@dataclass
class RemediationExecution:
    status: str
    worktree: str | None = None
    commands: list[dict[str, object]] = field(default_factory=list)
    changed_files: list[str] = field(default_factory=list)
    error: str | None = None
    commit: str | None = None


def execute_remediation(
    repository: str | Path,
    changes: Sequence[object],
    apply_change: Callable[[Path, object], None],
    validation_commands: Sequence[Sequence[str]],
    *,
    evidence_verified: bool | None = None,
    evidence_envelope: dict | None = None,
    evidence_artifact: bytes | dict | None = None,
    evidence_verifier=None,
    release_evidence: bool = False,
    evidence_env: dict[str, str] | None = None,
    cosign_bin: str = "cosign",
    base_dir: str | Path | None = None,
    timeout_seconds: int = 600,
    commit_message: str | None = None,
    approval_token: str | None = None,
    approval_secret: str | None = None,
    remediation_id: str | None = None,
    validation_working_directory: str | Path | None = None,
) -> RemediationExecution:
    """Apply supplied changes and run all validation commands in a worktree."""
    if evidence_envelope is not None:
        if evidence_artifact is None or (evidence_verifier is None and not release_evidence):
            return RemediationExecution(status="blocked", error="evidence verifier and artifact are required")
        try:
            if release_evidence:
                evidence_verified = verify_release_evidence(
                    evidence_envelope, evidence_artifact, env=evidence_env, cosign_bin=cosign_bin,
                )
            else:
                evidence_verified = verify_evidence(evidence_envelope, evidence_artifact, evidence_verifier)
        except EvidenceVerificationError as exc:
            return RemediationExecution(status="blocked", error=str(exc))
    if evidence_verified is not True:
        return RemediationExecution(status="blocked", error="verified evidence is required")
    if approval_secret:
        if not approval_token or not remediation_id:
            return RemediationExecution(status="blocked", error="approval token and remediation id are required")
        try:
            verify_approval(approval_token, remediation_id, approval_secret)
        except ValueError as exc:
            return RemediationExecution(status="blocked", error=str(exc))
    if timeout_seconds < 1:
        raise ValueError("timeout_seconds must be positive")

    try:
        with RemediationWorktree(repository, base_dir) as worktree:
            validation_cwd = worktree
            if validation_working_directory:
                relative_validation_dir = Path(validation_working_directory)
                if relative_validation_dir.is_absolute() or ".." in relative_validation_dir.parts:
                    return RemediationExecution(status="blocked", worktree=str(worktree), error="validation working directory must be relative")
                validation_cwd = (worktree / relative_validation_dir).resolve()
                if worktree not in validation_cwd.parents or not validation_cwd.is_dir():
                    return RemediationExecution(status="blocked", worktree=str(worktree), error="validation working directory is unavailable")
            for change in changes:
                apply_change(worktree, change)
            command_results = []
            for command in validation_commands:
                if not command:
                    return RemediationExecution(status="failed", worktree=str(worktree), error="empty validation command")
                result = subprocess.run(
                    list(command), cwd=validation_cwd, check=False, capture_output=True,
                    text=True, timeout=timeout_seconds,
                )
                command_results.append({
                    "command": list(command), "returncode": result.returncode,
                    "stdout": bounded_output(result.stdout, int(os.environ.get("REMEDIATION_COMMAND_OUTPUT_BYTES", "2000"))),
                    "stderr": bounded_output(result.stderr, int(os.environ.get("REMEDIATION_COMMAND_OUTPUT_BYTES", "2000"))),
                    "failure_class": classify_validation_failure(result.returncode, result.stderr),
                })
                if result.returncode != 0:
                    return RemediationExecution(status="failed", worktree=str(worktree), commands=command_results, error=f"validation failed: {command[0]}")
            diff = subprocess.run(
                ["git", "diff", "--name-only"], cwd=worktree, check=True,
                capture_output=True, text=True,
            )
            changed_files = [line for line in diff.stdout.splitlines() if line]
            try:
                changed_files = guard_changed_files(
                    changed_files,
                    maximum=int(os.environ.get("REMEDIATION_MAX_CHANGED_FILES", "50")),
                )
            except ValueError as exc:
                return RemediationExecution(status="failed", worktree=str(worktree), commands=command_results, error=str(exc))
            commit = None
            if commit_message and changed_files:
                subprocess.run(["git", "add", "--all"], cwd=worktree, check=True, capture_output=True, text=True)
                committed = subprocess.run(
                    ["git", "-c", "user.name=Scrutineering", "-c", "user.email=security@example.invalid", "commit", "-m", commit_message],
                    cwd=worktree, check=True, capture_output=True, text=True,
                )
                commit = subprocess.run(
                    ["git", "rev-parse", "HEAD"], cwd=worktree, check=True,
                    capture_output=True, text=True,
                ).stdout.strip()
            return RemediationExecution(status="ready", worktree=str(worktree), commands=command_results, changed_files=changed_files, commit=commit)
    except subprocess.TimeoutExpired as exc:
        return RemediationExecution(status="failed", error=f"validation timed out: {exc.cmd}")
    except Exception as exc:
        return RemediationExecution(status="failed", error=str(exc))
