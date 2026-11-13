"""Authenticated, fail-closed handoff of a validated remediation commit."""

from __future__ import annotations

import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path


_BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")


def _git(repository: Path, *args: str, check: bool = True, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", "-C", str(repository), *args], check=check, capture_output=True, text=True, env=env)


def publish_remediation_branch(
    repository: str | Path,
    commit: str,
    branch_name: str,
    *,
    token: str | None = None,
    remote: str = "origin",
) -> dict[str, str]:
    """Create and push a new branch for a validated local commit.

    The branch must not already exist locally or remotely. Credentials are
    supplied through a short-lived askpass file and never added to the remote
    URL or command arguments.
    """
    root = Path(repository).resolve()
    if not _BRANCH_RE.fullmatch(branch_name) or branch_name.startswith(("/", ".", "-")) or ".." in branch_name.split("/"):
        raise ValueError("invalid remediation branch name")
    if not commit or any(char.isspace() for char in commit):
        raise ValueError("a commit SHA is required")
    if not remote or remote.startswith("-"):
        raise ValueError("invalid Git remote")
    _git(root, "cat-file", "-e", f"{commit}^{{commit}}")
    if _git(root, "show-ref", "--verify", f"refs/heads/{branch_name}", check=False).returncode == 0:
        raise ValueError("remediation branch already exists locally")
    if _git(root, "ls-remote", "--exit-code", "--heads", remote, f"refs/heads/{branch_name}", check=False).returncode == 0:
        raise ValueError("remediation branch already exists remotely")

    _git(root, "branch", branch_name, commit)
    askpass_path: str | None = None
    env = os.environ.copy()
    try:
        if token:
            with tempfile.NamedTemporaryFile("w", prefix="scrutineering-askpass-", delete=False) as askpass:
                askpass.write("#!/bin/sh\ncase \"$1\" in *Username*) echo x-access-token ;; *) echo \"$SCRUTINEERING_GIT_TOKEN\" ;; esac\n")
                askpass_path = askpass.name
            os.chmod(askpass_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            env.update({"GIT_ASKPASS": askpass_path, "GIT_TERMINAL_PROMPT": "0", "SCRUTINEERING_GIT_TOKEN": token})
        _git(root, "push", remote, f"{branch_name}:refs/heads/{branch_name}", env=env)
    except Exception:
        _git(root, "branch", "-D", branch_name, check=False)
        raise
    finally:
        if askpass_path:
            Path(askpass_path).unlink(missing_ok=True)
    return {"branch_name": branch_name, "commit": commit, "remote": remote}
