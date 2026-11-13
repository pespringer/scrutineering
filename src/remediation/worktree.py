"""Safe, isolated Git worktree lifecycle for remediation workers."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path


def _git_env(repository: Path) -> dict[str, str]:
    env = dict(os.environ)
    env.update({"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "safe.directory", "GIT_CONFIG_VALUE_0": str(repository)})
    return env


class RemediationWorktree:
    """Create a detached worktree and remove it when the context exits."""

    def __init__(self, repository: str | Path, base_dir: str | Path | None = None):
        self.repository = Path(repository).resolve()
        self.base_dir = Path(base_dir).resolve() if base_dir else None
        self.path: Path | None = None

    def __enter__(self) -> Path:
        result = subprocess.run(
            ["git", "-C", str(self.repository), "rev-parse", "--show-toplevel"],
            check=True, capture_output=True, text=True, env=_git_env(self.repository),
        )
        if Path(result.stdout.strip()).resolve() != self.repository:
            raise ValueError("repository must be a Git worktree root")
        self.path = Path(tempfile.mkdtemp(prefix="scrutineering-worktree-", dir=self.base_dir))
        try:
            subprocess.run(
                ["git", "-C", str(self.repository), "worktree", "add", "--detach", str(self.path), "HEAD"],
                check=True, capture_output=True, text=True, env=_git_env(self.repository),
            )
        except Exception:
            shutil.rmtree(self.path, ignore_errors=True)
            self.path = None
            raise
        return self.path

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        if self.path is None:
            return
        subprocess.run(
            ["git", "-C", str(self.repository), "worktree", "remove", "--force", str(self.path)],
            check=True, capture_output=True, text=True, env=_git_env(self.repository),
        )
        self.path = None
