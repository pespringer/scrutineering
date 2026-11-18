"""CycloneDX SBOM downloads for scans and images (docs/design/sbom-evidence.md)."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from sqlalchemy import select

from src.api.serializers import iso
from src.db.connection import get_session
from src.db.models import Image, Sbom

router = APIRouter()

MEDIA_TYPE = "application/vnd.cyclonedx+json"


def sbom_summary(sbom: Sbom | None) -> dict | None:
    """What a page shows before downloading: which scan, how many components, and the hash."""
    if sbom is None:
        return None
    return {
        "scan_id": sbom.scan_id,
        "format": sbom.format,
        "spec_version": sbom.spec_version,
        "components": sbom.components,
        "sha256": sbom.sha256,
        "created_at": iso(sbom.created_at),
    }


def latest_for_image(session, image_id: int) -> Sbom | None:
    return session.execute(
        select(Sbom).where(Sbom.image_id == image_id).order_by(Sbom.id.desc()).limit(1)
    ).scalar_one_or_none()


def _download(sbom: Sbom, image: Image | None) -> Response:
    name = (image.full_name if image else sbom.scan_id).replace("/", "_").replace(":", "_")
    return Response(
        content=sbom.document,
        media_type=MEDIA_TYPE,
        headers={
            "Content-Disposition": f'attachment; filename="{name}.cdx.json"',
            "X-Scrutineering-SBOM-SHA256": sbom.sha256,
            "X-Scrutineering-Scan-ID": sbom.scan_id,
        },
    )


@router.get("/scans/{scan_id}/sbom")
def scan_sbom(scan_id: str) -> Response:
    with get_session() as session:
        sbom = session.execute(select(Sbom).where(Sbom.scan_id == scan_id)).scalar_one_or_none()
        if sbom is None:
            raise HTTPException(status_code=404, detail="sbom_not_found")
        return _download(sbom, session.get(Image, sbom.image_id))


@router.get("/images/{image_id}/sbom")
def image_sbom(image_id: int) -> Response:
    """The SBOM of the image's latest scan that has one."""
    with get_session() as session:
        image = session.get(Image, image_id)
        sbom = latest_for_image(session, image_id) if image else None
        if sbom is None:
            raise HTTPException(status_code=404, detail="sbom_not_found")
        return _download(sbom, image)
