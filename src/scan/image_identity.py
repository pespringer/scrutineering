"""Canonical parsing and identity helpers for container image references."""

from __future__ import annotations

from dataclasses import dataclass

from src.db.models import ImageRegistry


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
        registry_hosts = {
            ImageRegistry.GHCR: "ghcr.io",
            ImageRegistry.GCR: "gcr.io",
        }
        prefix = "" if self.registry == ImageRegistry.DOCKER_HUB else f"{registry_hosts.get(self.registry, self.registry.value)}/"
        if self.digest:
            return f"{prefix}{self.repo_name}@{self.digest}"
        return f"{prefix}{self.repo_name}:{self.tag}"

    @property
    def identity_key(self) -> str:
        """Return the stable key used for evidence and deduplication."""
        return f"{self.registry.value}/{self.repo_name}@{self.digest}" if self.digest else self.reference


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

    first_segment = value.split("/", 1)[0]
    registry = ImageRegistry.DOCKER_HUB
    if first_segment in {"ghcr.io"}:
        registry = ImageRegistry.GHCR
        value = value.split("/", 1)[1]
    elif first_segment in {"gcr.io", "us.gcr.io", "eu.gcr.io", "asia.gcr.io"}:
        registry = ImageRegistry.GCR
        value = value.split("/", 1)[1]
    elif "." in first_segment or ":" in first_segment:
        registry = ImageRegistry.OTHER

    return ImageIdentity(registry=registry, repo_name=value, tag=tag, digest=digest)
