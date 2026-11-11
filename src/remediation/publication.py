"""Provider-neutral gates for handing validated artifacts to PR publishers."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .rollback import build_rollback_plan


@dataclass(frozen=True)
class PublicationPlan:
    provider: str
    repository: str
    head: str
    base: str
    idempotency_key: str
    rollback_command: tuple[str, ...]


def build_publication_plan(*, provider: str, repository: str, head: str, base: str, idempotency_key: str, commit: str, evidence_verified: bool, allowed_repositories: set[str]) -> PublicationPlan:
    provider = provider.strip().lower()
    if provider not in {"github", "gitlab"}:
        raise ValueError("publication provider is not supported")
    if repository not in allowed_repositories:
        raise ValueError("repository is not allowlisted")
    if base not in {"main", "master"}:
        raise ValueError("base branch is not protected")
    if not re.fullmatch(r"[A-Za-z0-9._/-]{1,256}", head) or ".." in head or head == base:
        raise ValueError("head branch is invalid")
    if not idempotency_key or len(idempotency_key) > 256:
        raise ValueError("idempotency key is required")
    if evidence_verified is not True:
        raise ValueError("verified evidence is required")
    return PublicationPlan(provider, repository, head, base, idempotency_key, build_rollback_plan(commit).command)
