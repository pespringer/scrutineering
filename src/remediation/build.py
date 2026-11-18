"""Check out an image's source and build a patched candidate image with BuildKit.

The source is cloned into a fresh temporary directory (never edited in place),
and the build runs on the rootless `buildkitd` service, so the worker needs
neither the Docker socket nor root. The candidate is pushed to the local
registry under `<repository>:scrutineering-candidate-<remediation id>`.
"""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from src.config import get_settings
from src.remediation.apply import FROM_LINE, Checkout, final_from
from src.remediation.sources import SourceError, SourceSettings, clone_url, github_repository

BUILD_TIMEOUT_SECONDS = 1800
CLONE_TIMEOUT_SECONDS = 300


class BuildError(RuntimeError):
    """The source could not be checked out or the candidate could not be built."""


def git(
    args: list[str],
    cwd: Path | None = None,
    global_config: Path | None = None,
    env: dict[str, str] | None = None,
    strip: bool = True,
) -> str:
    """Run git with no system or user config and no prompts. `env` adds variables (for example GIT_ASKPASS)."""
    base = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": str(global_config or os.devnull),
        **(env or {}),
    }
    try:
        result = subprocess.run(
            ["git", *args], cwd=cwd, env=base, capture_output=True, text=True, timeout=CLONE_TIMEOUT_SECONDS
        )
    except subprocess.TimeoutExpired as exc:
        raise BuildError(f"git {args[0]} timed out") from exc
    if result.returncode != 0:
        raise BuildError(f"git {args[0]} failed: {result.stderr.strip()[-800:]}")
    return result.stdout.strip() if strip else result.stdout


def askpass_env(workdir: Path, access_token: str) -> dict[str, str]:
    """Environment that lets git authenticate over https without the token in any URL or argument."""
    script = workdir / "askpass.sh"
    script.write_text(
        '#!/bin/sh\ncase "$1" in\n  *sername*) echo x-access-token ;;\n  *) echo "$SCRUTINEERING_GIT_TOKEN" ;;\nesac\n'
    )
    script.chmod(stat.S_IRWXU)
    return {"GIT_ASKPASS": str(script), "SCRUTINEERING_GIT_TOKEN": access_token}


def checkout(settings: SourceSettings, workdir: Path) -> tuple[Checkout, str]:
    """Clone the source at its ref into `workdir/source`. Returns the checkout and the commit it is on."""
    try:
        origin = clone_url(settings.repository) if settings.is_remote else str(settings.local_path())
    except SourceError as exc:
        raise BuildError(str(exc)) from exc
    if not settings.is_remote and not Path(origin, ".git").exists():
        raise BuildError(f"{settings.repository} is not a git repository under the sources root")
    root = workdir / "source"
    # Local sources are mounted read-only and owned by another user. Git honours
    # safe.directory only from protected (global or system) config, so give the clone its own.
    config = workdir / "gitconfig"
    config.write_text(f"[safe]\n\tdirectory = {origin}\n\tdirectory = {origin}/.git\n")
    # A github.com source may be private: clone it with GITHUB_TOKEN, the token publication uses.
    token = get_settings().github_token.get_secret_value() if github_repository(settings.repository) else ""
    auth = askpass_env(workdir, token) if token else None
    git(["clone", "--quiet", "--no-hardlinks", "--", origin, str(root)], global_config=config, env=auth)
    if settings.ref != "HEAD":
        git(["checkout", "--quiet", "--detach", settings.ref], cwd=root)
    commit = git(["rev-parse", "HEAD"], cwd=root)
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
    git(["add", "--intent-to-add", "--all"], cwd=source.root)
    return git(["diff", "--no-color", "--no-ext-diff"], cwd=source.root, strip=False)


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
            get_settings().buildkit_host,
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


TEST_STAGE = "scrutineering-test"
CANDIDATE_STAGE = "scrutineering-candidate"
MAX_TEST_OUTPUT = 3000


def test_dockerfile(dockerfile_text: str, command: list[str]) -> str:
    """The Dockerfile plus a stage that runs `command` in its final stage (exec form, same WORKDIR and USER)."""
    lines = dockerfile_text.splitlines()
    index = final_from(lines)
    match = FROM_LINE.match(lines[index])
    named = re.search(r"\s+AS\s+(\S+)\s*$", match["rest"], re.IGNORECASE)
    stage = named.group(1) if named else CANDIDATE_STAGE
    if not named:
        lines[index] = f"{lines[index].rstrip()} AS {CANDIDATE_STAGE}"
    lines += ["", f"FROM {stage} AS {TEST_STAGE}", f"RUN {json.dumps(command)}"]
    return "\n".join(lines) + "\n"


def run_tests(source: Checkout, build_args: dict[str, str], command: list[str]) -> None:
    """Run the source's test command inside the candidate image, through the same BuildKit build.

    The candidate's layers come from the build cache, so the command sees exactly the image that
    was pushed. Nothing is exported or pushed, and the patched source is not touched.
    """
    with tempfile.TemporaryDirectory(prefix="scrutineering-test-") as scratch:
        dockerfile = Path(scratch) / "Dockerfile"
        dockerfile.write_text(test_dockerfile(source.dockerfile.read_text(), command))
        buildctl = [
            "buildctl",
            "--addr",
            get_settings().buildkit_host,
            "build",
            "--frontend",
            "dockerfile.v0",
            "--local",
            f"context={source.context}",
            "--local",
            f"dockerfile={scratch}",
            "--opt",
            "filename=Dockerfile",
            "--opt",
            f"target={TEST_STAGE}",
            *[part for key, value in sorted(build_args.items()) for part in ("--opt", f"build-arg:{key}={value}")],
            "--progress",
            "plain",
        ]
        try:
            result = subprocess.run(buildctl, capture_output=True, text=True, timeout=BUILD_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired as exc:
            raise BuildError(f"the tests timed out after {BUILD_TIMEOUT_SECONDS}s") from exc
        except FileNotFoundError as exc:
            raise BuildError("buildctl is not installed in the worker") from exc
        if result.returncode != 0:
            shown = " ".join(command)
            raise BuildError(f"the candidate's tests failed ({shown}):\n{result.stderr[-MAX_TEST_OUTPUT:]}")
