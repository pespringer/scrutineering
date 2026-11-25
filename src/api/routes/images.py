"""Image inventory and image detail."""

from __future__ import annotations

from collections import defaultdict

from fastapi import APIRouter, HTTPException, Query, Request
from sqlalchemy import func

from src.scan.deployments import container_counts
from src.api.routes.sboms import latest_for_image, sbom_summary
from src.scan.runtime_discovery import running_since
from src.db.connection import get_session
from src.db.models import (
    AuditEventType,
    Image,
    ScanFinding,
)
from src.api.schemas import BulkIdsRequest
from src.api.serializers import (
    source_payload,
    finding_payload,
    image_payload,
    paginate,
)
from src.api.routes._access import record_operator_event, severity_filter
from src.api.roles import require_action

router = APIRouter()


@router.get("/images")
def image_inventory(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    search: str | None = Query(default=None, max_length=200),
    severity: str | None = Query(default=None),
    running: bool | None = Query(default=None, description="Only images runtime discovery saw running"),
) -> dict:
    severity_value = severity_filter(severity)
    with get_session() as session:
        query = session.query(Image).filter_by(active=True)
        if running:
            query = query.filter(Image.last_seen_running_at >= running_since())
        if search:
            query = query.filter(Image.repo_name.ilike(f"%{search.strip()}%"))
        if severity_value:
            query = query.filter(
                Image.id.in_(
                    session.query(ScanFinding.image_id).filter(
                        ScanFinding.resolved_at.is_(None), ScanFinding.severity == severity_value.value
                    )
                )
            )
        total = query.order_by(None).count()
        images = query.order_by(Image.repo_name.asc()).offset(offset).limit(limit).all()
        image_ids = [image.id for image in images]
        findings = (
            session.query(ScanFinding)
            .filter(
                ScanFinding.image_id.in_(image_ids),
                ScanFinding.resolved_at.is_(None),
            )
            .all()
            if image_ids
            else []
        )
        resolved_counts = (
            dict(
                session.query(ScanFinding.image_id, func.count(ScanFinding.id))
                .filter(
                    ScanFinding.image_id.in_(image_ids),
                    ScanFinding.resolved_at.is_not(None),
                )
                .group_by(ScanFinding.image_id)
                .all()
            )
            if image_ids
            else {}
        )
        containers = container_counts(session, image_ids)
    findings_by_image: dict[int, list[ScanFinding]] = defaultdict(list)
    for finding in findings:
        findings_by_image[finding.image_id].append(finding)
    no_containers = {"containers": 0, "stale_containers": 0}
    return paginate(
        [
            {
                **image_payload(image, findings_by_image[image.id], resolved_counts.get(image.id, 0)),
                **containers.get(image.id, no_containers),
            }
            for image in images
        ],
        limit,
        offset,
        total,
    )


@router.post("/images/bulk-archive")
def bulk_archive_images(payload: BulkIdsRequest, request: Request) -> dict:
    require_action(request, "images.archive")
    image_ids = [int(value) for value in payload.ids]
    archived: list[int] = []
    with get_session() as session:
        for image in session.query(Image).filter(Image.id.in_(image_ids), Image.active.is_(True)).all():
            image.active = False
            archived.append(image.id)
            record_operator_event(
                session,
                request,
                AuditEventType.CONFIG_CHANGED,
                str(image.id),
                {"action": "archive_image"},
                entity_type="image",
            )
    return {"requested": image_ids, "archived": archived, "count": len(archived)}


@router.get("/images/{image_id}")
def image_detail(
    image_id: int,
    severity: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict:
    severity_value = severity_filter(severity)
    with get_session() as session:
        image = session.get(Image, image_id)
        if image is None:
            raise HTTPException(status_code=404, detail="image_not_found")
        query = session.query(ScanFinding).filter(ScanFinding.image_id == image_id, ScanFinding.resolved_at.is_(None))
        if severity_value:
            query = query.filter(ScanFinding.severity == severity_value.value)
        total = query.order_by(None).count()
        findings = query.order_by(ScanFinding.severity.asc(), ScanFinding.id.asc()).offset(offset).limit(limit).all()
        all_findings = (
            session.query(ScanFinding).filter(ScanFinding.image_id == image_id, ScanFinding.resolved_at.is_(None)).all()
        )
        resolved_count = (
            session.query(ScanFinding)
            .filter(ScanFinding.image_id == image_id, ScanFinding.resolved_at.is_not(None))
            .count()
        )
        sbom = sbom_summary(latest_for_image(session, image_id))
    return {
        "image": {
            **image_payload(image, all_findings, resolved_count),
            "source": source_payload(image.source),
            "sbom": sbom,
        },
        "findings": [finding_payload(finding) for finding in findings],
        "findings_page": paginate([finding_payload(finding) for finding in findings], limit, offset, total),
    }
