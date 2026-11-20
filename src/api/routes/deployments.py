"""Which containers run an image, and whether they run its latest scanned build.

See docs/design/deployment-observation.md. The rules live in src/scan/deployments.py; this module
only shapes them for the dashboard.
"""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, HTTPException

from src.api.serializers import iso
from src.db.connection import get_session
from src.db.models import Deployment, Image
from src.scan.deployments import deployment_state, utcnow, latest_scan_digest, running_rows

router = APIRouter()

GONE_SHOWN = timedelta(hours=24)


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
    now = utcnow()
    with get_session() as session:
        if session.get(Image, image_id) is None:
            raise HTTPException(status_code=404, detail="image_not_found")
        digest = latest_scan_digest(session, image_id)
        running = running_rows(session, [image_id], now)
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
