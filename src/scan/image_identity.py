"""Canonical parsing and identity helpers for container image references.

`repo_name` always keeps the registry host for non-Docker-Hub images, so an
identity can be turned back into the exact reference a scanner needs. Docker Hub
names are normalized to their short form (`docker.io/library/nginx` -> `nginx`).
"""

from __future__ import annotations

from dataclasses import dataclass

from src.db.models import ImageRegistry

_DOCKER_HUB_HOSTS = ("docker.io", "index.docker.io", "registry-1.docker.io")
_DOCKER_HUB_API_HOST = "registry-1.docker.io"


def _classify(host: str | None) -> ImageRegistry:
    if host is None:
        return ImageRegistry.DOCKER_HUB
    if host == "ghcr.io":
        return ImageRegistry.GHCR
    if host == "gcr.io" or host.endswith(".gcr.io") or host.endswith("-docker.pkg.dev"):
        return ImageRegistry.GCR
    if ".dkr.ecr." in host and host.endswith(".amazonaws.com"):
        return ImageRegistry.ECR
    if host == "registry.gitlab.com":
        return ImageRegistry.GITLAB
    if host == "quay.io":
        return ImageRegistry.QUAY
    return ImageRegistry.OTHER


def _split_host(name: str) -> tuple[str | None, str]:
    """Split `host/path`; the first segment is a host only if it looks like one."""
    if "/" not in name:
        return None, name
    first, rest = name.split("/", 1)
    if "." in first or ":" in first or first == "localhost":
        return first, rest
    return None, name


@dataclass(frozen=True)
class ImageIdentity:
    """Normalized image coordinates and optional immutable digest."""

    registry: ImageRegistry
    repo_name: str
    tag: str = "latest"
    digest: str | None = None

    @property
    def is_immutable(self) -> bool:
        return self.digest is not None

    @property
    def reference(self) -> str:
        """The reference to hand to a scanner: `repo@digest` if pinned, else `repo:tag`."""
        if self.digest:
            return f"{self.repo_name}@{self.digest}"
        return f"{self.repo_name}:{self.tag}"

    @property
    def identity_key(self) -> str:
        """Return the stable key used for evidence and deduplication."""
        return self.reference

    @property
    def host(self) -> str:
        """Registry API host (Docker Hub resolves to its registry endpoint)."""
        host, _ = _split_host(self.repo_name)
        return host or _DOCKER_HUB_API_HOST

    @property
    def repository(self) -> str:
        """Repository path on the registry API, e.g. `library/nginx` or `acme/api`."""
        host, path = _split_host(self.repo_name)
        if host is None and "/" not in path:
            return f"library/{path}"
        return path


def parse_image_reference(image_name: str) -> ImageIdentity:
    """Parse a Docker-style reference, including ``@sha256:...`` digests."""
    value = str(image_name or "").strip()
    if not value or any(char.isspace() for char in value):
        raise ValueError("image_name must not be empty")

    digest = None
    if "@" in value:
        value, digest = value.rsplit("@", 1)
        if not digest.startswith("sha256:") or len(digest) != 71:
            raise ValueError("image digest must use a 64-character sha256 value")

    tag = "latest"
    if ":" in value:
        candidate_repo, candidate_tag = value.rsplit(":", 1)
        if "/" not in candidate_tag:
            value, tag = candidate_repo, candidate_tag

    host, path = _split_host(value)
    if host in _DOCKER_HUB_HOSTS:
        host = None
    if host is None and path.startswith("library/") and path.count("/") == 1:
        path = path.removeprefix("library/")
    if not path:
        raise ValueError("image_name must include a repository")

    repo_name = f"{host}/{path}" if host else path
    return ImageIdentity(registry=_classify(host), repo_name=repo_name, tag=tag, digest=digest)
