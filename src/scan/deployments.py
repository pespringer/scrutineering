"""Deployments: which containers run a tracked image, and which build each one runs.

See docs/design/deployment-observation.md. Runtime discovery records one row per container of a
scannable image (Docker only: containerd has no inspect here, so nothing is recorded there). A row
is marked gone when a run no longer lists the container; a run that couldn't list or inspect
marks nothing gone. Current or stale is derived when read, from the row's running digests and the
image's latest scan, so there is no second status to disagree with the first.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Iterable

from celery import shared_task
from sqlalchemy import select

from src.db.models import Deployment, FindingObservation, Remediation, Scan, ScanFinding, ScanStatus
from src.remediation.evidence import FINISHED_SCANS, finished_scan
from src.scan.runtime_discovery import running_since

logger = logging.getLogger(__name__)

DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
RETENTION = timedelta(days=30)


@dataclass(frozen=True)
class Observed:
    """One running container, reduced to what's stored."""

    container_id: str
    name: str
    image_ref: str
    running_digests: list[str]
    started_at: datetime | None


def _digest(value: str) -> str | None:
    """`sha256:<hex>` from an image ID or a `repo@sha256:<hex>` RepoDigest; None otherwise."""
    candidate = str(value or "").rpartition("@")[2].strip()
    return candidate if DIGEST.fullmatch(candidate) else None


def running_digests(image_id: str, repo_digests: Iterable[str] | None) -> list[str]:
    """The digests a container's build is known by: its image ID plus its registry digests, sorted."""
    found = {_digest(image_id), *(_digest(item) for item in repo_digests or [])}
    return sorted(digest for digest in found if digest)


def parse_started_at(value: str) -> datetime | None:
    """Docker's `State.StartedAt` (RFC 3339, nanoseconds) as naive UTC; None for an unset or odd value."""
    match = re.fullmatch(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})", str(value or ""))
    if not match:
        return None
    base, fraction, zone = match.groups()
    micros = (fraction or "0")[:6].ljust(6, "0")
    text = f"{base}.{micros}{'+00:00' if zone == 'Z' else zone}"
    try:
        parsed = datetime.fromisoformat(text).astimezone(timezone.utc).replace(tzinfo=None)
    except ValueError:
        return None
    return None if parsed.year < 1971 else parsed  # Docker reports 0001-01-01 for "never started"


def deployment_state(digests: Iterable[str], scan_digest: str | None) -> str:
    """`current` if the container runs the scanned build, `stale` if not, `unknown` without a scan digest."""
    if not scan_digest:
        return "unknown"
    return "current" if scan_digest in set(digests) else "stale"


async def observe(
    containers: list[dict[str, Any]],
    scannable: list[str],
    inspect: Callable[[list[str]], Awaitable[list[dict[str, str]] | None]],
    repo_digests: Callable[[str], Awaitable[list[str] | None]],
) -> list[Observed] | None:
    """Inspect the listed containers of scannable images. None if Docker couldn't be asked."""
    wanted = set(scannable)
    references = {
        str(container.get("id") or ""): str(container.get("image") or "")
        for container in containers
        if container.get("id") and container.get("image") in wanted
    }
    details = await inspect(list(references))
    if details is None:
        return None
    digests_by_image: dict[str, list[str] | None] = {}
    observed = []
    for detail in details:
        container_id, image_id = detail.get("Id", ""), detail.get("Image", "")
        reference = references.get(container_id)
        if not reference:
            continue
        if image_id not in digests_by_image:
            digests_by_image[image_id] = await repo_digests(image_id) if image_id else None
        observed.append(
            Observed(
                container_id=container_id,
                name=detail.get("Name", "").lstrip("/")[:256],
                image_ref=reference,
                running_digests=running_digests(image_id, digests_by_image[image_id]),
                started_at=parse_started_at(detail.get("State.StartedAt", "")),
            )
        )
    return observed


def record(observed: list[Observed], listed_ids: set[str], *, now: datetime) -> dict[str, int]:
    """Upsert each observed container, and mark gone the running rows whose container isn't listed."""
    from src.db.connection import get_session
    from src.db.models import Deployment
    from src.scan.records import get_or_create_image, scan_identity

    recorded = 0
    with get_session() as session:
        for item in observed:
            try:
                image = get_or_create_image(session, scan_identity(item.image_ref))
            except ValueError:
                continue
            row = session.query(Deployment).filter_by(container_id=item.container_id).first()
            if row is None:
                row = Deployment(container_id=item.container_id, first_seen_at=now)
                session.add(row)
            row.name, row.image_ref, row.image_id = item.name, item.image_ref, image.id
            row.running_digests, row.started_at = item.running_digests, item.started_at
            row.last_seen_at, row.gone_at = now, None
            recorded += 1
        session.flush()
        seen = listed_ids | {item.container_id for item in observed}
        gone = 0
        for row in session.query(Deployment).filter(Deployment.gone_at.is_(None)).all():
            if row.container_id not in seen:
                row.gone_at = now
                gone += 1
    return {"recorded": recorded, "gone": gone}


def prune(now: datetime | None = None) -> int:
    """Delete rows gone for more than RETENTION."""
    from sqlalchemy import delete

    from src.db.connection import get_session
    from src.db.models import Deployment

    cutoff = (now or datetime.now(timezone.utc).replace(tzinfo=None)) - RETENTION
    with get_session() as session:
        deleted = session.execute(
            delete(Deployment).where(Deployment.gone_at.is_not(None), Deployment.gone_at < cutoff)
        ).rowcount
    if deleted:
        logger.info("pruned %d deployments gone for over %d days", deleted, RETENTION.days)
    return deleted


@shared_task(name="src.scan.deployments.prune_deployments", acks_late=True, ignore_result=True)
def prune_deployments() -> int:
    """Daily, from beat."""
    return prune()


# -- Reading: which containers count as running, and which run the latest or the fixed build ---------
#
# A container counts as running when discovery listed it within the Running window (30 minutes, as
# for the Running badge), so rows whose discovery stopped don't count forever.


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def running_rows(session, image_ids: list[int], now: datetime) -> list[Deployment]:
    if not image_ids:
        return []
    return (
        session.query(Deployment)
        .filter(
            Deployment.image_id.in_(image_ids),
            Deployment.gone_at.is_(None),
            Deployment.last_seen_at >= running_since(now),
        )
        .order_by(Deployment.name.asc(), Deployment.id.asc())
        .all()
    )


def latest_scan_digest(session, image_id: int) -> str | None:
    """The digest of the image's latest finished scan; None if it has none or was scanned by tag."""
    return session.execute(
        select(Scan.image_digest)
        .where(Scan.image_id == image_id, Scan.status.in_(FINISHED_SCANS))
        .order_by(Scan.started_at.desc(), Scan.id.desc())
        .limit(1)
    ).scalar_one_or_none()


def container_counts(session, image_ids: list[int], now: datetime | None = None) -> dict[int, dict[str, int]]:
    """Per image: running containers, and how many of them are stale. Images without any are left out."""
    rows = running_rows(session, image_ids, now or utcnow())
    digests = {image_id: latest_scan_digest(session, image_id) for image_id in {row.image_id for row in rows}}
    counts: dict[int, dict[str, int]] = {}
    for row in rows:
        entry = counts.setdefault(row.image_id, {"containers": 0, "stale_containers": 0})
        entry["containers"] += 1
        if deployment_state(row.running_digests or [], digests[row.image_id]) == "stale":
            entry["stale_containers"] += 1
    return counts


def fixed_digests(session, remediation: Remediation) -> set[str]:
    """Builds that carry the fix: the scan that completed it, and later complete scans without the targets."""
    before = finished_scan(session, remediation.image_id, started_by=remediation.created_at)
    after = finished_scan(session, remediation.image_id, started_by=remediation.completed_at)
    if after is None or (before is not None and after.scan_id == before.scan_id):
        return set()
    found = {after.image_digest} if after.image_digest else set()
    targets = {finding.vuln_key for finding in remediation.findings if finding.vuln_key}
    later = session.execute(
        select(Scan).where(
            Scan.image_id == remediation.image_id,
            Scan.status == ScanStatus.COMPLETED.value,
            Scan.started_at > after.started_at,
            Scan.image_digest.is_not(None),
        )
    ).scalars()
    for scan in later:
        present = session.execute(
            select(ScanFinding.id)
            .join(FindingObservation, FindingObservation.finding_id == ScanFinding.id)
            .where(FindingObservation.scan_id == scan.scan_id, ScanFinding.vuln_key.in_(targets))
            .limit(1)
        ).first()
        if present is None:
            found.add(scan.image_digest)
    return found


def remediation_deployment(session, remediation: Remediation, now: datetime | None = None) -> dict | None:
    """For a completed remediation: its image's running containers, and how many run a fixed build.

    `fixed` is None when no fixed build has a digest (scanned by tag): Scrutineering won't guess.
    """
    if str(getattr(remediation.status, "value", remediation.status)) != "completed":
        return None
    rows = running_rows(session, [remediation.image_id], now or utcnow())
    digests = fixed_digests(session, remediation)
    fixed = [row for row in rows if digests & set(row.running_digests or [])]
    return {
        "containers": len(rows),
        "fixed": len(fixed) if digests else None,
        "not_fixed": [row.name for row in rows if row not in fixed] if digests else [],
    }
