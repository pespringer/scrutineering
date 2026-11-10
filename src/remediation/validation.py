"""Ordered validation gates required before remediation publication."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Sequence

REQUIRED_PHASES = ("install", "test", "build", "sbom", "rescan")
DEFAULT_ALLOWED_COMMANDS = {"npm", "npm ci", "npm test", "pytest", "python", "python3", "docker", "syft", "trivy", "grype", "true", "false"}


def build_provider_validation_commands(provider: str, ecosystem: str) -> dict[str, list[str]]:
    """Return deterministic validation gates for a supported CI provider/ecosystem."""
    provider_key = str(provider or "").strip().lower()
    ecosystem_key = str(ecosystem or "").strip().lower()
    if provider_key not in {"github", "github_actions", "gitlab"}:
        raise ValueError("validation provider is not supported")
    if ecosystem_key in {"node", "nodejs", "javascript", "typescript"}:
        return {
            "install": ["npm", "ci"],
            "test": ["npm", "test"],
            "build": ["npm", "run", "build"],
            "sbom": ["syft", ".", "-o", "spdx-json"],
            "rescan": ["trivy", "fs", ".", "--exit-code", "1"],
        }
    if ecosystem_key in {"python", "py"}:
        return {
            "install": ["python", "-m", "pip", "install", "-r", "requirements.txt"],
            "test": ["pytest", "tests", "-q"],
            "build": ["python", "-m", "compileall", "src"],
            "sbom": ["syft", ".", "-o", "spdx-json"],
            "rescan": ["trivy", "fs", ".", "--exit-code", "1"],
        }
    raise ValueError("validation ecosystem is not supported")


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
    allowed_commands: set[str] | None = None,
    phase_timeouts: Mapping[str, int] | None = None,
    max_argument_length: int = 4096,
) -> ValidationResult:
    """Run all required gates in order; missing gates fail closed."""
    if timeout_seconds < 1:
        raise ValueError("timeout_seconds must be positive")
    if max_argument_length < 1: raise ValueError("max_argument_length must be positive")
    missing = [phase for phase in REQUIRED_PHASES if not commands.get(phase)]
    if missing:
        return ValidationResult(status="blocked", error=f"missing validation phases: {', '.join(missing)}")

    results = []
    allowed = allowed_commands or DEFAULT_ALLOWED_COMMANDS
    for phase in REQUIRED_PHASES:
        command = list(commands[phase])
        if any(len(str(argument)) > max_argument_length for argument in command):
            return ValidationResult(status="blocked", phases=results, error=f"{phase} command argument is too long")
        normalized = " ".join(command[:2]) if len(command) > 1 and command[0] == "npm" else command[0]
        executable = Path(command[0]).name
        if command[0] not in {entry.split()[0] for entry in allowed} and executable not in {entry.split()[0] for entry in allowed} and normalized not in allowed:
            return ValidationResult(status="blocked", phases=results, error=f"{phase} command is not allowlisted")
        timeout = (phase_timeouts or {}).get(phase, timeout_seconds)
        if timeout < 1: return ValidationResult(status="blocked", phases=results, error=f"{phase} timeout must be positive")
        try:
            completed = subprocess.run(command, cwd=worktree, capture_output=True, text=True, check=False, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            results.append({"phase": phase, "command": command, "returncode": -1, "stdout": "", "stderr": "timed out"})
            return ValidationResult(status="failed", phases=results, error=f"{phase} phase timed out")
        result = {
            "phase": phase, "command": command, "returncode": completed.returncode,
            "stdout": completed.stdout[-2000:], "stderr": completed.stderr[-2000:],
        }
        results.append(result)
        if completed.returncode != 0:
            return ValidationResult(status="failed", phases=results, error=f"{phase} phase failed")
    return ValidationResult(status="passed", phases=results)
