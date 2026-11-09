"""Ordered validation gates required before remediation publication."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Sequence

REQUIRED_PHASES = ("install", "test", "build", "sbom", "rescan")


@dataclass
class ValidationResult:
    status: str
    phases: list[dict[str, object]] = field(default_factory=list)
    error: str | None = None


def run_validation_pipeline(
    worktree: str | Path,
    commands: Mapping[str, Sequence[str]],
    *,
    timeout_seconds: int = 1800,
) -> ValidationResult:
    """Run all required gates in order; missing gates fail closed."""
    if timeout_seconds < 1:
        raise ValueError("timeout_seconds must be positive")
    missing = [phase for phase in REQUIRED_PHASES if not commands.get(phase)]
    if missing:
        return ValidationResult(status="blocked", error=f"missing validation phases: {', '.join(missing)}")

    results = []
    for phase in REQUIRED_PHASES:
        command = list(commands[phase])
        completed = subprocess.run(command, cwd=worktree, capture_output=True, text=True, check=False, timeout=timeout_seconds)
        result = {
            "phase": phase, "command": command, "returncode": completed.returncode,
            "stdout": completed.stdout[-2000:], "stderr": completed.stderr[-2000:],
        }
        results.append(result)
        if completed.returncode != 0:
            return ValidationResult(status="failed", phases=results, error=f"{phase} phase failed")
    return ValidationResult(status="passed", phases=results)
