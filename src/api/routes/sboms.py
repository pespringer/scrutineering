"""CycloneDX SBOM downloads, their signatures, and the public keys to verify them (docs/design/sbom-evidence.md)."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse, Response
from sqlalchemy import select

from src.api.serializers import iso
from src.db.connection import get_session
from src.db.models import Image, Sbom, SigningKey

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
        "signed": bool(sbom.signature),
        "key_id": sbom.key_id,
        "created_at": iso(sbom.created_at),
    }


def latest_for_image(session, image_id: int) -> Sbom | None:
    return session.execute(
        select(Sbom).where(Sbom.image_id == image_id).order_by(Sbom.id.desc()).limit(1)
    ).scalar_one_or_none()


def _download(sbom: Sbom, image: Image | None) -> Response:
    name = (image.full_name if image else sbom.scan_id).replace("/", "_").replace(":", "_")
    headers = {
        "Content-Disposition": f'attachment; filename="{name}.cdx.json"',
        "X-Scrutineering-SBOM-SHA256": sbom.sha256,
        "X-Scrutineering-Scan-ID": sbom.scan_id,
    }
    if sbom.signature:
        headers.update({"X-Scrutineering-Signature": sbom.signature, "X-Scrutineering-Key-ID": sbom.key_id or ""})
    return Response(content=sbom.document, media_type=MEDIA_TYPE, headers=headers)


def _scan_sbom(session, scan_id: str) -> Sbom:
    sbom = session.execute(select(Sbom).where(Sbom.scan_id == scan_id)).scalar_one_or_none()
    if sbom is None:
        raise HTTPException(status_code=404, detail="sbom_not_found")
    return sbom


@router.get("/scans/{scan_id}/sbom")
def scan_sbom(scan_id: str) -> Response:
    with get_session() as session:
        sbom = _scan_sbom(session, scan_id)
        return _download(sbom, session.get(Image, sbom.image_id))


@router.get("/scans/{scan_id}/sbom.sig")
def scan_sbom_signature(scan_id: str) -> PlainTextResponse:
    """The base64 signature, as `cosign verify-blob --signature` reads it."""
    with get_session() as session:
        sbom = _scan_sbom(session, scan_id)
        if not sbom.signature:
            raise HTTPException(status_code=404, detail="sbom_not_signed")
        return PlainTextResponse(
            sbom.signature + "\n",
            headers={
                "Content-Disposition": f'attachment; filename="{scan_id}.cdx.json.sig"',
                "X-Scrutineering-Key-ID": sbom.key_id or "",
            },
        )


@router.get("/images/{image_id}/sbom")
def image_sbom(image_id: int) -> Response:
    """The SBOM of the image's latest scan that has one."""
    with get_session() as session:
        image = session.get(Image, image_id)
        sbom = latest_for_image(session, image_id) if image else None
        if sbom is None:
            raise HTTPException(status_code=404, detail="sbom_not_found")
        return _download(sbom, image)


@router.get("/signing-keys")
def signing_keys() -> dict:
    """Every public key this instance has signed with, newest first; verify with the one named in `key_id`."""
    with get_session() as session:
        keys = session.query(SigningKey).order_by(SigningKey.id.desc()).all()
        return {
            "keys": [
                {"key_id": key.key_id, "public_key_pem": key.public_key_pem, "created_at": iso(key.created_at)}
                for key in keys
            ]
        }


@router.get("/signing-keys/{fingerprint}.pem")
def signing_key_pem(fingerprint: str) -> PlainTextResponse:
    """One public key as a PEM file; `fingerprint` is the hex part of its key ID."""
    with get_session() as session:
        key = session.query(SigningKey).filter_by(key_id=f"sha256:{fingerprint}").first()
        if key is None:
            raise HTTPException(status_code=404, detail="signing_key_not_found")
        return PlainTextResponse(
            key.public_key_pem,
            media_type="application/x-pem-file",
            headers={"Content-Disposition": f'attachment; filename="scrutineering-{fingerprint[:12]}.pem"'},
        )
