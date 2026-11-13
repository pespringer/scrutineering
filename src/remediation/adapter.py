"""Explicit repository adapter for guarded remediation execution."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping, Sequence

from .edits import replace_text
from .executor import RemediationExecution, execute_remediation
from .validation import DEFAULT_ALLOWED_COMMANDS, REQUIRED_PHASES, build_provider_validation_commands


def build_exact_match_changes(actions: Sequence[Mapping[str, object]]) -> list[dict[str, str]]:
    """Normalize persisted actions and reject incomplete or unsafe edits."""
    changes = []
    for action in actions:
        file_path = str(action.get("file_path") or "")
        before = str(action.get("before_value") or "")
        after = str(action.get("after_value") or "")
        target = Path(file_path)
        if not file_path or target.is_absolute() or ".." in target.parts or not before or before == after:
            raise ValueError("remediation actions require safe, non-empty exact-match edits")
        changes.append({"file_path": file_path, "expected": before, "replacement": after})
    if not changes:
        raise ValueError("at least one remediation action is required")
    return changes


def build_validation_sequence(provider: str, ecosystem: str) -> list[list[str]]:
    """Build the required ordered install/test/build/SBOM/rescan command list."""
    commands = build_provider_validation_commands(provider, ecosystem)
    sequence = []
    allowed = {entry.split()[0] for entry in DEFAULT_ALLOWED_COMMANDS}
    for phase in REQUIRED_PHASES:
        command = list(commands[phase])
        if not command or command[0] not in allowed:
            raise ValueError(f"{phase} command is not allowlisted")
        sequence.append(command)
    return sequence


def load_release_evidence(envelope_path: str | Path, artifact_path: str | Path) -> tuple[dict, bytes]:
    envelope = json.loads(Path(envelope_path).read_text(encoding="utf-8"))
    artifact = Path(artifact_path).read_bytes()
    return envelope, artifact


def execute_repository_adapter(
    repository: str | Path,
    actions: Sequence[Mapping[str, object]],
    validation_commands: Sequence[Sequence[str]],
    *,
    evidence_envelope: dict,
    evidence_artifact: bytes,
    evidence_env: dict[str, str] | None = None,
    commit_message: str = "Apply verified security remediation",
    remediation_id: str,
    validation_working_directory: str | Path | None = None,
) -> RemediationExecution:
    changes = build_exact_match_changes(actions)
    return execute_remediation(
        repository,
        changes,
        lambda worktree, change: replace_text(worktree, change["file_path"], change["expected"], change["replacement"]),
        validation_commands,
        evidence_envelope=evidence_envelope,
        evidence_artifact=evidence_artifact,
        release_evidence=True,
        evidence_env=evidence_env,
        commit_message=commit_message,
        remediation_id=remediation_id,
        validation_working_directory=validation_working_directory,
    )
