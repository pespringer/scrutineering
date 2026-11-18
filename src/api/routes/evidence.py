"""Signed evidence bundles for remediations (docs/design/sbom-evidence.md).

The bundle includes the patch, so it needs the remediator role, like the remediation page.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import PlainTextResponse, Response
from sqlalchemy import select

from src.api.routes._access import require_role
from src.api.serializers import iso
from src.db.connection import get_session
from src.db.models import EvidenceBundle

router = APIRouter()


def latest_bundle(session, remediation_id: int) -> EvidenceBundle | None:
    return session.execute(
        select(EvidenceBundle)
        .where(EvidenceBundle.remediation_id == remediation_id)
        .order_by(EvidenceBundle.id.desc())
        .limit(1)
    ).scalar_one_or_none()


def evidence_summary(bundle: EvidenceBundle | None) -> dict | None:
    if bundle is None:
        return None
    return {
        "outcome": bundle.outcome,
        "sha256": bundle.sha256,
        "signed": bool(bundle.signature),
        "key_id": bundle.key_id,
        "created_at": iso(bundle.created_at),
    }


def _bundle(remediation_id: int) -> EvidenceBundle:
    with get_session() as session:
        bundle = latest_bundle(session, remediation_id)
        if bundle is None:
            raise HTTPException(status_code=404, detail="evidence_not_found")
        session.expunge(bundle)
        return bundle


@router.get("/remediations/{remediation_id}/evidence")
def remediation_evidence(remediation_id: int, request: Request) -> Response:
    require_role(request, "remediator", "security-operator")
    bundle = _bundle(remediation_id)
    headers = {
        "Content-Disposition": f'attachment; filename="remediation-{remediation_id}-evidence.json"',
        "X-Scrutineering-Evidence-SHA256": bundle.sha256,
    }
    if bundle.signature:
        headers.update({"X-Scrutineering-Signature": bundle.signature, "X-Scrutineering-Key-ID": bundle.key_id or ""})
    return Response(content=bundle.document, media_type="application/json", headers=headers)


@router.get("/remediations/{remediation_id}/evidence.sig")
def remediation_evidence_signature(remediation_id: int, request: Request) -> PlainTextResponse:
    require_role(request, "remediator", "security-operator")
    bundle = _bundle(remediation_id)
    if not bundle.signature:
        raise HTTPException(status_code=404, detail="evidence_not_signed")
    return PlainTextResponse(
        bundle.signature + "\n",
        headers={
            "Content-Disposition": f'attachment; filename="remediation-{remediation_id}-evidence.json.sig"',
            "X-Scrutineering-Key-ID": bundle.key_id or "",
        },
    )
