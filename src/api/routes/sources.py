"""Connect an image to the repository it is built from."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from src.api.routes._access import record_operator_event
from src.api.roles import require_action
from src.api.schemas import ImageSourceRequest
from src.api.serializers import source_payload
from src.db.connection import get_session
from src.db.models import AuditEventType, Image, ImageSource
from src.remediation.sources import SourceError, SourceSettings

router = APIRouter()


def _image(session, image_id: int) -> Image:
    image = session.get(Image, image_id)
    if image is None:
        raise HTTPException(status_code=404, detail="image_not_found")
    return image


@router.get("/images/{image_id}/source")
def get_image_source(image_id: int) -> dict:
    with get_session() as session:
        image = _image(session, image_id)
        return {"image_id": image_id, "source": source_payload(image.source)}


@router.put("/images/{image_id}/source")
def put_image_source(image_id: int, payload: ImageSourceRequest, request: Request) -> dict:
    """Create or replace the image's source. Validated here; resolved by the worker at execution time."""
    require_action(request, "sources.manage")
    try:
        settings = SourceSettings.validated(**payload.model_dump())
    except SourceError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    actor = getattr(request.state, "principal_id", "dashboard-service")
    with get_session() as session:
        image = _image(session, image_id)
        source = image.source or ImageSource(image_id=image_id)
        source.repository = settings.repository
        source.ref = settings.ref
        source.dockerfile_path = settings.dockerfile_path
        source.build_context = settings.build_context
        source.build_args = settings.build_args
        source.test_command = settings.test_command
        source.updated_by = actor
        session.add(source)
        session.flush()
        record_operator_event(
            session,
            request,
            AuditEventType.CONFIG_CHANGED,
            str(image_id),
            {"action": "image_source_set", "repository": settings.repository, "ref": settings.ref},
            entity_type="image",
        )
        session.refresh(source)
        return {"image_id": image_id, "source": source_payload(source)}


@router.delete("/images/{image_id}/source")
def delete_image_source(image_id: int, request: Request) -> dict:
    require_action(request, "sources.manage")
    with get_session() as session:
        image = _image(session, image_id)
        if image.source is not None:
            session.delete(image.source)
            record_operator_event(
                session,
                request,
                AuditEventType.CONFIG_CHANGED,
                str(image_id),
                {"action": "image_source_removed"},
                entity_type="image",
            )
    return {"image_id": image_id, "source": None}
