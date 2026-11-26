"""The preflight of `make registry-gc` (scripts/registry-gc.py): what garbage collection would break.

See docs/design/registry-management.md. It runs in the API container, which reaches both the database
and the registry, prints one line per problem, and exits 1 if there is any. Running containers come
from runtime discovery's records, and from the host's Docker, which the script reads and passes on
stdin: discovery skips some (when it's off or filtered, or when the tag has moved since). Collection itself runs in
a one-off registry container while the registry is stopped, so nothing can push during it.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.orm import Session

from src.config import get_settings
from src.db.connection import get_session
from src.db.models import Deployment, Image, Remediation, Scan, ScanStatus
from src.remediation.state_machine import ACTIVE
from src.scan.deployments import RETENTION, utcnow
from src.scan.image_identity import parse_image_reference
from src.scan.registry_catalog import RegistryClient, RegistryError, catalog


DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


@dataclass(frozen=True)
class Running:
    name: str
    image_ref: str
    digests: frozenset[str]


def from_docker(document: str) -> list[Running]:
    """Containers as the script reads them from Docker: `[{"name", "image_ref", "digests"}]`."""
    found = []
    for item in json.loads(document or "[]"):
        if not isinstance(item, dict):
            continue
        digests = item.get("digests") if isinstance(item.get("digests"), list) else []
        found.append(
            Running(
                str(item.get("name") or "")[:256],
                str(item.get("image_ref") or ""),
                frozenset(digest for digest in digests if isinstance(digest, str) and DIGEST.fullmatch(digest)),
            )
        )
    return found


def _local_repository(reference: str) -> str | None:
    """The repository path of a reference to the bundled registry, under either of its names; else None."""
    settings = get_settings()
    hosts = {settings.local_registry_host.strip(), settings.local_registry_public_host.strip()} - {""}
    try:
        identity = parse_image_reference(reference)
    except ValueError:
        return None
    host, _, repository = identity.repo_name.partition("/")
    return repository if host in hosts and repository else None


def _busy(session: Session) -> list[str]:
    problems = []
    building = session.query(Remediation.id).filter(Remediation.status.in_(ACTIVE)).order_by(Remediation.id)
    for (remediation_id,) in building:
        problems.append(f"Remediation {remediation_id} is building or verifying its candidate. Wait for it to finish.")
    active = (ScanStatus.PENDING.value, ScanStatus.RUNNING.value)
    scans = session.query(Scan.scan_id, Image.repo_name, Image.tag).join(Image, Scan.image_id == Image.id)
    for scan_id, repo_name, tag in scans.filter(Scan.status.in_(active)).order_by(Scan.id):
        if _local_repository(f"{repo_name}:{tag}"):
            problems.append(f"Scan {scan_id} of {repo_name}:{tag} is pending or running. Wait for it, or cancel it.")
    return problems


def _kept(client: RegistryClient) -> tuple[set[tuple[str, str]], list[str]]:
    """What the tags keep, by repository and digest: indexes, manifests, configs and layers."""
    kept: set[tuple[str, str]] = set()
    unreadable = []
    for item in catalog(client):
        if item.summary is None:
            unreadable.append(f"{item.repository}:{item.tag}")
            continue
        kept.update((item.repository, digest) for digest in item.summary.blobs)
    return kept, unreadable


def _running(session: Session, now: datetime, docker: list[Running]) -> list[tuple[Running, str]]:
    """Containers of the bundled registry's images, with their repository, each named once."""
    rows = session.query(Deployment.name, Deployment.image_ref, Deployment.running_digests).filter(
        Deployment.gone_at.is_(None), Deployment.last_seen_at >= now - RETENTION
    )
    recorded = [Running(row.name, row.image_ref, frozenset(row.running_digests or [])) for row in rows]
    found: dict[tuple[str, frozenset[str]], tuple[Running, str]] = {}
    for item in [*docker, *recorded]:
        if repository := _local_repository(item.image_ref):
            found.setdefault((item.name, item.digests), (item, repository))
    return list(found.values())


def _orphaned(session: Session, client: RegistryClient, now: datetime, docker: list[Running]) -> list[str]:
    """Containers running a build that the registry stores, but that no tag keeps: collection removes it."""
    ours = _running(session, now, docker)
    if not ours:
        return []
    kept, unreadable = _kept(client)
    problems = []
    for item, repository in ours:
        if any((repository, digest) in kept for digest in item.digests):
            continue
        if any(client.holds(repository, digest) for digest in sorted(item.digests)):
            problems.append(
                f"Container {item.name} runs {item.image_ref}, a build no tag keeps, so collection would remove it. "
                "Tag that build, or stop the container."
            )
    if problems and unreadable:
        problems.append("These tags couldn't be read, and may keep it: " + ", ".join(unreadable))
    return problems


def preflight(now: datetime | None = None, docker: list[Running] | None = None) -> list[str]:
    """Why collection shouldn't run now. Empty when it may. `docker` is what the host's Docker runs."""
    client = RegistryClient.local()
    with get_session() as session:
        try:
            return _busy(session) + _orphaned(session, client, now or utcnow(), docker or [])
        except RegistryError as error:
            return [f"The registry can't be read: {error}."]


def main() -> int:
    """With `--containers -`, the host's containers are read from stdin."""
    docker = from_docker(sys.stdin.read()) if sys.argv[1:] == ["--containers", "-"] else []
    problems = preflight(docker=docker)
    for problem in problems:
        print(problem)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
