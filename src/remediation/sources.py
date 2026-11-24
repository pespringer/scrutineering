"""Validate image source settings and resolve them to a working checkout.

A source tells a remediation where an image is built from. The API validates
the settings it is given; the worker (which holds the checkouts) resolves them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from src.config import get_settings

GITHUB_WEB = "https://github.com"
_URL = re.compile(r"^https://[A-Za-z0-9.-]+(:\d+)?/[A-Za-z0-9._~/-]+$")
_REF = re.compile(r"^[A-Za-z0-9._/-]{1,256}$")
_ARG_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_GITHUB_REPOSITORY = re.compile(
    r"^https://github\.com/(?P<owner>[A-Za-z0-9][A-Za-z0-9-]{0,38})/(?P<name>[A-Za-z0-9._-]{1,100}?)(?:\.git)?$"
)


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
        root = Path(sources_root or get_settings().remediation_sources_root).resolve()
        path = (root / self.repository).resolve()
        if path != root and root not in path.parents:
            raise SourceError("repository path escapes the sources root")
        return path


SNAPSHOT_FIELDS = ("repository", "ref", "dockerfile_path", "build_context", "build_args", "test_command")


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


def snapshot(record) -> dict:
    """The copy of an `ImageSource` a remediation keeps from its proposal (docs/design/security-hardening.md)."""
    copy = {name: getattr(record, name) for name in SNAPSHOT_FIELDS}
    copy["build_args"] = dict(copy["build_args"] or {})
    copy["test_command"] = list(copy["test_command"]) if copy["test_command"] else None
    return copy


def settings_from_snapshot(copy: dict) -> SourceSettings:
    """SourceSettings for a remediation's copy of its source."""
    return SourceSettings.validated(**{name: copy.get(name) for name in SNAPSHOT_FIELDS})


@dataclass(frozen=True)
class PublicationTarget:
    """Where a verified fix for a source can be published: a provider and the project's path on it."""

    provider: str  # "github"
    path: str  # "owner/name"


def publication_target(source_url: str | None) -> PublicationTarget | None:
    """The provider and project a source publishes to, or None when its fixes are applied by hand."""
    repository = github_repository(source_url)
    return PublicationTarget("github", repository) if repository else None


def source_token(source_url: str | None) -> str:
    """The token that clones a remote source: its publication provider's, or none."""
    target = publication_target(source_url)
    if target is not None and target.provider == "github":
        return get_settings().github_token.get_secret_value()
    return ""


def github_repository(source_url: str | None) -> str | None:
    """`owner/name` when a source is an https://github.com repository (the one publication target), else None."""
    match = _GITHUB_REPOSITORY.fullmatch(str(source_url or "").rstrip("/"))
    return f"{match['owner']}/{match['name']}" if match else None


def clone_url(repository: str) -> str:
    """What git clones for a remote source: github.com sources as `<GITHUB_WEB>/<owner>/<name>.git`."""
    name = github_repository(repository)
    return f"{GITHUB_WEB}/{name}.git" if name else repository
