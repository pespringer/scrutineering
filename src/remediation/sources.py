"""Validate image source settings and resolve them to a working checkout.

A source tells a remediation where an image is built from. The API validates
the settings it is given; the worker (which holds the checkouts) resolves them.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

DEFAULT_SOURCES_ROOT = "/workspace/sources"
_URL = re.compile(r"^https://[A-Za-z0-9.-]+(:\d+)?/[A-Za-z0-9._~/-]+$")
_REF = re.compile(r"^[A-Za-z0-9._/-]{1,256}$")
_ARG_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


class SourceError(ValueError):
    """The source settings are invalid or cannot be resolved."""


def _relative_path(value: str, name: str, *, allow_dot: bool = False) -> str:
    text = str(value or "").strip()
    if not text:
        raise SourceError(f"{name} is required")
    path = PurePosixPath(text)
    if path.is_absolute() or ".." in path.parts or "\\" in text:
        raise SourceError(f"{name} must be a relative path inside the repository")
    normalized = str(path)
    if normalized == "." and not allow_dot:
        raise SourceError(f"{name} must name a file")
    return normalized


@dataclass(frozen=True)
class SourceSettings:
    repository: str
    ref: str = "HEAD"
    dockerfile_path: str = "Dockerfile"
    build_context: str = "."
    build_args: dict[str, str] = field(default_factory=dict)
    test_command: list[str] | None = None

    @property
    def is_remote(self) -> bool:
        return self.repository.startswith("https://")

    @classmethod
    def validated(
        cls,
        *,
        repository: str,
        ref: str = "HEAD",
        dockerfile_path: str = "Dockerfile",
        build_context: str = ".",
        build_args: dict | None = None,
        test_command: list | None = None,
    ) -> "SourceSettings":
        repository = str(repository or "").strip().rstrip("/")
        if repository.startswith("https://"):
            if not _URL.fullmatch(repository):
                raise SourceError("repository URL must be a plain https:// git URL without credentials")
        elif "://" in repository or repository.startswith("git@"):
            raise SourceError("remote repositories must use an https:// URL")
        else:
            repository = _relative_path(repository, "repository")
        ref = str(ref or "HEAD").strip()
        if not _REF.fullmatch(ref) or ".." in ref or ref.startswith("-"):
            raise SourceError("ref must be a branch, tag, or commit name")
        args = {}
        for key, value in (build_args or {}).items():
            if not _ARG_NAME.fullmatch(str(key)):
                raise SourceError(f"build argument name {key!r} is invalid")
            args[str(key)] = str(value)
        command = None
        if test_command:
            if not isinstance(test_command, list) or not all(isinstance(part, str) and part for part in test_command):
                raise SourceError('test_command must be a list of arguments, e.g. ["npm", "test"]')
            command = list(test_command)
        return cls(
            repository=repository,
            ref=ref,
            dockerfile_path=_relative_path(dockerfile_path, "dockerfile_path"),
            build_context=_relative_path(build_context, "build_context", allow_dot=True),
            build_args=args,
            test_command=command,
        )

    def local_path(self, sources_root: str | Path | None = None) -> Path:
        """Absolute path of a local repository, which must stay inside the sources root."""
        if self.is_remote:
            raise SourceError("remote repositories have no local path")
        root = Path(sources_root or os.environ.get("REMEDIATION_SOURCES_ROOT", DEFAULT_SOURCES_ROOT)).resolve()
        path = (root / self.repository).resolve()
        if path != root and root not in path.parents:
            raise SourceError("repository path escapes the sources root")
        return path


def settings_from_record(record) -> SourceSettings:
    """SourceSettings for an `ImageSource` row."""
    return SourceSettings.validated(
        repository=record.repository,
        ref=record.ref,
        dockerfile_path=record.dockerfile_path,
        build_context=record.build_context,
        build_args=record.build_args or {},
        test_command=record.test_command,
    )
