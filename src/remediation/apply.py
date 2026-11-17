"""Apply planned fix actions to a checked-out image source.

Each strategy changes the source the way a developer would: the package manager
updates lockfiles, requirement pins are rewritten, and the Dockerfile gains an
OS-package upgrade or a newer base-image tag. Nothing here builds or scans.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from src.remediation.planner import version_key

COMMAND_TIMEOUT_SECONDS = 600
OS_UPGRADE_COMMANDS = {
    "apk": "apk add --no-cache --upgrade {packages}",
    "apt": (
        "apt-get update && apt-get install -y --no-install-recommends --only-upgrade {packages} "
        "&& rm -rf /var/lib/apt/lists/*"
    ),
    "rpm": "(dnf -y upgrade {packages} || yum -y update {packages}) && (dnf clean all || yum clean all)",
}
_PACKAGE_NAME = re.compile(r"^[A-Za-z0-9@][A-Za-z0-9@._+/-]{0,213}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+~:-]{0,127}$")
_FROM = re.compile(r"^(?P<lead>\s*FROM\s+)(?P<flags>(?:--\S+\s+)*)(?P<image>\S+)(?P<rest>.*)$", re.IGNORECASE)


class ApplyError(RuntimeError):
    """An action could not be applied to the source."""


@dataclass
class Checkout:
    root: Path
    dockerfile: Path
    context: Path


def _safe(value: str, pattern: re.Pattern, what: str) -> str:
    if not value or not pattern.fullmatch(value):
        raise ApplyError(f"refusing unusual {what}: {value!r}")
    return value


def _run(command: list[str], cwd: Path) -> None:
    """Run a package-manager command with no credentials from the worker's environment."""
    passed_on = {"PATH", "HOME", "LANG", "HTTPS_PROXY", "NO_PROXY"}
    env = {key: value for key, value in os.environ.items() if key in passed_on}
    try:
        result = subprocess.run(
            command, cwd=cwd, env=env, capture_output=True, text=True, timeout=COMMAND_TIMEOUT_SECONDS, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise ApplyError(f"{command[0]} timed out after {COMMAND_TIMEOUT_SECONDS}s") from exc
    except FileNotFoundError as exc:
        raise ApplyError(f"{command[0]} is not installed in the worker") from exc
    if result.returncode != 0:
        raise ApplyError(f"{' '.join(command[:3])} failed: {(result.stderr or result.stdout)[-1500:]}")


def _package_dirs(context: Path, manifest: str) -> list[Path]:
    return sorted(
        path.parent for path in context.rglob(manifest) if "node_modules" not in path.parts and ".git" not in path.parts
    )


def update_npm(checkout: Checkout, package: str, version: str) -> list[str]:
    """Move `package` to `version` with npm: a direct dependency is reinstalled, a transitive one overridden."""
    _safe(package, _PACKAGE_NAME, "package name")
    _safe(version, _VERSION, "version")
    changed = []
    for directory in _package_dirs(checkout.context, "package.json"):
        manifest_path = directory / "package.json"
        manifest = json.loads(manifest_path.read_text())
        lock = directory / "package-lock.json"
        lock_text = lock.read_text() if lock.exists() else ""
        sections = ("dependencies", "devDependencies", "optionalDependencies")
        direct = next((section for section in sections if package in manifest.get(section, {})), None)
        if direct is None and f'"node_modules/{package}"' not in lock_text:
            continue
        if direct:
            flag = {"devDependencies": "--save-dev", "optionalDependencies": "--save-optional"}.get(direct, "--save")
            command = ["npm", "install", f"{package}@{version}", flag, "--save-exact"]
        else:
            manifest.setdefault("overrides", {})[package] = version
            manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
            command = ["npm", "install"]
        _run([*command, "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"], directory)
        changed.append(str(directory.relative_to(checkout.root)))
    if not changed:
        raise ApplyError(f"{package} is not in any package.json or package-lock.json under the build context")
    return changed


def update_pip(checkout: Checkout, package: str, version: str) -> list[str]:
    """Rewrite `package==old` pins to `package==version` in requirements files."""
    _safe(package, _PACKAGE_NAME, "package name")
    _safe(version, _VERSION, "version")
    # PEP 503: names compare case-insensitively with runs of -, _ and . treated as equal.
    name = "[-_.]+".join(re.escape(part) for part in re.split(r"[-_.]+", package))
    pin = re.compile(rf"^(?P<name>{name})(?P<extras>\[[^\]]*\])?\s*==\s*[^\s;#]+", re.IGNORECASE | re.MULTILINE)
    changed = []
    for path in sorted(checkout.context.rglob("requirements*.txt")):
        text = path.read_text()
        updated = pin.sub(lambda m: f"{m['name']}{m['extras'] or ''}=={version}", text)
        if updated != text:
            path.write_text(updated)
            changed.append(str(path.relative_to(checkout.root)))
    if not changed:
        raise ApplyError(f"{package} is not pinned with == in any requirements file under the build context")
    return changed


def _final_from(lines: list[str]) -> int:
    indexes = [index for index, line in enumerate(lines) if _FROM.match(line)]
    if not indexes:
        raise ApplyError("the Dockerfile has no FROM line")
    return indexes[-1]


def upgrade_os_packages(checkout: Checkout, family: str, packages: dict[str, str]) -> list[str]:
    """Upgrade the packages in the final build stage, right after its FROM line."""
    if family not in OS_UPGRADE_COMMANDS:
        raise ApplyError(f"no upgrade command for {family} packages")
    names = " ".join(_safe(name, _PACKAGE_NAME, "package name") for name in sorted(packages))
    lines = checkout.dockerfile.read_text().splitlines()
    index = _final_from(lines)
    command = OS_UPGRADE_COMMANDS[family].format(packages=names)
    lines.insert(index + 1, f"# Scrutineering: upgrade OS packages with known fixes\nRUN {command}")
    checkout.dockerfile.write_text("\n".join(lines) + "\n")
    return [str(checkout.dockerfile.relative_to(checkout.root))]


def newer_tag(current: str, tags: list[str]) -> str | None:
    """The highest tag in the same release line: same major version, same suffix, same precision.

    `18.12-alpine` → `18.20-alpine`; `3.11.4-slim-bookworm` → `3.11.9-slim-bookworm` (not `3.12.x`
    unless only the major is fixed, as in `3-slim`).
    """
    match = re.fullmatch(r"(\d+(?:\.\d+)*)(.*)", current)
    if not match:
        return None
    numbers, suffix = match.group(1).split("."), match.group(2)
    best_tag, best_version = None, version_key(match.group(1))
    for tag in tags:
        candidate = re.fullmatch(r"(\d+(?:\.\d+)*)(.*)", tag)
        if not candidate or candidate.group(2) != suffix:
            continue
        parts = candidate.group(1).split(".")
        if len(parts) != len(numbers) or parts[0] != numbers[0]:
            continue
        if len(numbers) > 2 and parts[1] != numbers[1]:
            continue  # x.y.z lines stay on x.y; x.y lines may move to a newer minor
        if version_key(candidate.group(1)) > best_version:
            best_tag, best_version = tag, version_key(candidate.group(1))
    return best_tag


def bump_base_image(checkout: Checkout, list_tags: Callable[[str], list[str]]) -> tuple[list[str], str, str]:
    """Rewrite the final stage's FROM to the newest tag of the same line. Returns (files, old, new)."""
    lines = checkout.dockerfile.read_text().splitlines()
    index = _final_from(lines)
    match = _FROM.match(lines[index])
    image = match["image"]
    if "$" in image or "@" in image or ":" not in image.rsplit("/", 1)[-1]:
        raise ApplyError(f"cannot bump base image {image!r}: it must be a literal name:tag")
    repository, tag = image.rsplit(":", 1)
    stages = {m.group(1).lower() for line in lines if (m := re.search(r"\sAS\s+(\S+)\s*$", line, re.IGNORECASE))}
    if repository.lower() in stages:
        raise ApplyError("the final stage builds FROM another stage; bump that stage's base by hand")
    target = newer_tag(tag, list_tags(repository))
    if target is None:
        raise ApplyError(f"no newer tag than {image} in the same release line")
    lines[index] = f"{match['lead']}{match['flags']}{repository}:{target}{match['rest']}"
    checkout.dockerfile.write_text("\n".join(lines) + "\n")
    return [str(checkout.dockerfile.relative_to(checkout.root))], image, f"{repository}:{target}"


def apply_action(checkout: Checkout, detail: dict, list_tags: Callable[[str], list[str]]) -> dict:
    """Apply one planned action (its stored `detail`) and report what changed."""
    strategy = detail.get("strategy")
    if strategy == "dependency_update":
        updater = {"npm": update_npm, "pip": update_pip}.get(detail.get("ecosystem") or "")
        if updater is None:
            raise ApplyError(f"no updater for {detail.get('ecosystem')} packages")
        return {"files": updater(checkout, detail["package"], detail["to_version"])}
    if strategy == "os_package_upgrade":
        return {"files": upgrade_os_packages(checkout, detail.get("ecosystem") or "", detail.get("packages") or {})}
    if strategy == "base_image_bump":
        files, old, new = bump_base_image(checkout, list_tags)
        return {"files": files, "from_image": old, "to_image": new}
    raise ApplyError(f"unknown fix strategy {strategy!r}")
