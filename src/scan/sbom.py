"""CycloneDX SBOMs for completed and partial image scans (docs/design/sbom-evidence.md).

After a scan finishes, Trivy runs once more on the same reference and writes the image's SBOM from
the cache the scan filled. A failed SBOM never fails the scan. Each image keeps the SBOM of its
latest scan that has one, and every SBOM an evidence bundle cites; a daily sweep removes the rest.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging

from celery import shared_task
from sqlalchemy import delete, func, select

from src.db.connection import get_session
from src.db.models import Sbom

logger = logging.getLogger(__name__)


def _count_components(components: list | None) -> int:
    """Components, including nested ones."""
    return sum(1 + _count_components(item.get("components")) for item in components or [] if isinstance(item, dict))


def _sign(document: str):
    """Sign the stored bytes; an unsigned SBOM is better than none if the key can't be used."""
    from src import signing

    try:
        return signing.sign(document.encode())
    except Exception as exc:  # noqa: BLE001 - logged; the SBOM is kept unsigned
        logger.error("could not sign an SBOM, keeping it unsigned: %s", exc)
        return None


def store(scan_id: str, image_id: int, document: str) -> Sbom:
    """Save one scan's SBOM exactly as written, with its SHA-256, a component count, and a signature."""
    parsed = json.loads(document)
    signature = _sign(document)
    with get_session() as session:
        sbom = Sbom(
            scan_id=scan_id,
            image_id=image_id,
            format="cyclonedx-json",
            spec_version=str(parsed.get("specVersion") or "") or None,
            components=_count_components(parsed.get("components")),
            document=document,
            sha256=hashlib.sha256(document.encode()).hexdigest(),
            signature=signature.value if signature else None,
            key_id=signature.key_id if signature else None,
        )
        session.add(sbom)
        session.flush()
        session.expunge(sbom)
        return sbom


def generate(scan_id: str, image_id: int, target: str, scanner) -> str:
    """Write and store the SBOM for a finished scan. Returns `stored` or `failed`; never raises."""
    try:
        document = asyncio.run(scanner.sbom(target))
        sbom = store(scan_id, image_id, document)
    except Exception as exc:  # noqa: BLE001 - the scan's result stands without its SBOM
        logger.warning("SBOM for scan %s failed: %s", scan_id, exc)
        return "failed"
    logger.info("SBOM for scan %s: %d components", scan_id, sbom.components)
    return "stored"


def prune() -> int:
    """Keep each image's newest SBOM, and every SBOM an evidence bundle cites; delete the rest."""
    from src.db.models import EvidenceBundle

    with get_session() as session:
        newest = select(func.max(Sbom.id)).group_by(Sbom.image_id)
        cited = (
            select(EvidenceBundle.before_scan_id)
            .where(EvidenceBundle.before_scan_id.is_not(None))
            .union(select(EvidenceBundle.after_scan_id).where(EvidenceBundle.after_scan_id.is_not(None)))
        )
        deleted = session.execute(delete(Sbom).where(Sbom.id.not_in(newest), Sbom.scan_id.not_in(cited))).rowcount
    if deleted:
        logger.info("pruned %d superseded SBOMs", deleted)
    return deleted


@shared_task(name="src.scan.sbom.prune_sboms", acks_late=True, ignore_result=True)
def prune_sboms() -> int:
    """Daily, from beat."""
    return prune()
