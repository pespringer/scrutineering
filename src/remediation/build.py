"""Check out an image's source and build a patched candidate image with BuildKit.

The source is cloned into a fresh temporary directory (never edited in place),
and the build runs on the rootless `buildkitd` service, so the worker needs
neither the Docker socket nor root. The candidate is pushed to the local
registry under `<repository>:scrutineering-candidate-<remediation id>`.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from src.remediation.apply import Checkout
from src.remediation.sources import SourceError, SourceSettings

BUILD_TIMEOUT_SECONDS = 1800
CLONE_TIMEOUT_SECONDS = 300
DEFAULT_BUILDKIT_HOST = "tcp://buildkitd:1234"


class BuildError(RuntimeError):
    """The source could not be checked out or the candidate could not be built."""


def _git(args: list[str], cwd: Path | None = None, global_config: Path | None = None) -> str:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": str(global_config or os.devnull),
    }
    try:
        result = subprocess.run(
            ["git", *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=CLONE_TIMEOUT_SECONDS
        )
    except subprocess.TimeoutExpired as exc:
        raise BuildError(f"git {args[0]} timed out") from exc
    if result.returncode != 0:
        raise BuildError(f"git {args[0]} failed: {result.stderr.strip()[-800:]}")
    return result.stdout.strip()


def checkout(settings: SourceSettings, workdir: Path) -> tuple[Checkout, str]:
    """Clone the source at its ref into `workdir/source`. Returns the checkout and the commit it is on."""
    try:
        origin = settings.repository if settings.is_remote else str(settings.local_path())
    except SourceError as exc:
        raise BuildError(str(exc)) from exc
    if not settings.is_remote and not Path(origin, ".git").exists():
        raise BuildError(f"{settings.repository} is not a git repository under the sources root")
    root = workdir / "source"
    # Local sources are mounted read-only and owned by another user. Git honours
    # safe.directory only from protected (global or system) config, so give the clone its own.
    config = workdir / "gitconfig"
    config.write_text(f"[safe]\n\tdirectory = {origin}\n\tdirectory = {origin}/.git\n")
    _git(["clone", "--quiet", "--no-hardlinks", "--", origin, str(root)], global_config=config)
    if settings.ref != "HEAD":
        _git(["checkout", "--quiet", "--detach", settings.ref], cwd=root)
    commit = _git(["rev-parse", "HEAD"], cwd=root)
    dockerfile = (root / settings.dockerfile_path).resolve()
    context = (root / settings.build_context).resolve()
    for path, what in ((dockerfile, "Dockerfile"), (context, "build context")):
        if path != root and root.resolve() not in path.parents:
            raise BuildError(f"{what} escapes the repository")
    if not dockerfile.is_file():
        raise BuildError(f"{settings.dockerfile_path} does not exist at {settings.ref}")
    if not context.is_dir():
        raise BuildError(f"build context {settings.build_context} does not exist at {settings.ref}")
    return Checkout(root=root, dockerfile=dockerfile, context=context), commit


def diff(source: Checkout) -> str:
    """The patch the actions produced, as `git diff` text (new files included)."""
    _git(["add", "--intent-to-add", "--all"], cwd=source.root)
    return _git(["diff", "--no-color", "--no-ext-diff"], cwd=source.root)


@dataclass
class BuiltImage:
    reference: str
    digest: str


def build_and_push(source: Checkout, build_args: dict[str, str], reference: str) -> BuiltImage:
    """Build the patched source with buildctl and push it to `reference` in the local registry."""
    with tempfile.TemporaryDirectory(prefix="scrutineering-build-") as scratch:
        metadata = Path(scratch) / "metadata.json"
        command = [
            "buildctl",
            "--addr",
            os.environ.get("BUILDKIT_HOST", DEFAULT_BUILDKIT_HOST),
            "build",
            "--frontend",
            "dockerfile.v0",
            "--local",
            f"context={source.context}",
            "--local",
            f"dockerfile={source.dockerfile.parent}",
            "--opt",
            f"filename={source.dockerfile.name}",
            *[part for key, value in sorted(build_args.items()) for part in ("--opt", f"build-arg:{key}={value}")],
            "--output",
            f"type=image,name={reference},push=true,registry.insecure=true",
            "--metadata-file",
            str(metadata),
            "--progress",
            "plain",
        ]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=BUILD_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired as exc:
            raise BuildError(f"the build timed out after {BUILD_TIMEOUT_SECONDS}s") from exc
        except FileNotFoundError as exc:
            raise BuildError("buildctl is not installed in the worker") from exc
        if result.returncode != 0:
            raise BuildError(f"the build failed:\n{result.stderr[-3000:]}")
        try:
            digest = json.loads(metadata.read_text())["containerimage.digest"]
        except (OSError, ValueError, KeyError) as exc:
            raise BuildError("the build finished without reporting an image digest") from exc
    return BuiltImage(reference=reference, digest=digest)
