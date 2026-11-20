"""Which containers run an image, and whether they run its latest scanned or fixed build.

See docs/design/deployment-observation.md. Rows come from runtime discovery (src/scan/deployments.py).
A container counts as running when discovery listed it within the Running window (30 minutes, as
for the Running badge); gone ones are shown for 24 hours. Current, stale and unknown are derived
here, on every read, and never stored.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException
from sqlalchemy import select

from src.api.serializers import iso
from src.db.connection import get_session
from src.db.models import Deployment, FindingObservation, Image, Remediation, Scan, ScanFinding, ScanStatus
from src.remediation.evidence import FINISHED_SCANS, finished_scan
from src.scan.deployments import deployment_state
from src.scan.runtime_discovery import running_since

router = APIRouter()

GONE_SHOWN = timedelta(hours=24)


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _running(session, image_ids: list[int], now: datetime) -> list[Deployment]:
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
    rows = _running(session, image_ids, now or _now())
    digests = {image_id: latest_scan_digest(session, image_id) for image_id in {row.image_id for row in rows}}
    counts: dict[int, dict[str, int]] = {}
    for row in rows:
        entry = counts.setdefault(row.image_id, {"containers": 0, "stale_containers": 0})
        entry["containers"] += 1
        if deployment_state(row.running_digests or [], digests[row.image_id]) == "stale":
            entry["stale_containers"] += 1
    return counts


def _container(row: Deployment, state: str) -> dict:
    return {
        "container_id": row.container_id,
        "name": row.name,
        "image_ref": row.image_ref,
        "state": state,
        "running_digests": list(row.running_digests or []),
        "started_at": iso(row.started_at),
        "last_seen_at": iso(row.last_seen_at),
        "gone_at": iso(row.gone_at),
    }


@router.get("/images/{image_id}/deployments")
def image_deployments(image_id: int) -> dict:
    """The image's running containers, and those gone within 24 hours, each current, stale or unknown."""
    now = _now()
    with get_session() as session:
        if session.get(Image, image_id) is None:
            raise HTTPException(status_code=404, detail="image_not_found")
        digest = latest_scan_digest(session, image_id)
        running = _running(session, [image_id], now)
        gone = (
            session.query(Deployment)
            .filter(Deployment.image_id == image_id, Deployment.gone_at >= now - GONE_SHOWN)
            .order_by(Deployment.gone_at.desc(), Deployment.id.desc())
            .all()
        )
        return {
            "image_id": image_id,
            "scan_digest": digest,
            "containers": [_container(row, deployment_state(row.running_digests or [], digest)) for row in running],
            "gone": [_container(row, deployment_state(row.running_digests or [], digest)) for row in gone],
        }


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
    rows = _running(session, [remediation.image_id], now or _now())
    digests = fixed_digests(session, remediation)
    fixed = [row for row in rows if digests & set(row.running_digests or [])]
    return {
        "containers": len(rows),
        "fixed": len(fixed) if digests else None,
        "not_fixed": [row.name for row in rows if row not in fixed] if digests else [],
    }
