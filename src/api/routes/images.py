"""Image inventory, image detail, and the local registry catalog."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from urllib.parse import quote
from urllib.request import Request as UrlRequest, urlopen

from fastapi import APIRouter, HTTPException, Query, Request
from sqlalchemy import func

from src.config import get_settings
from src.db.connection import get_session
from src.db.models import (
    AuditEventType,
    Image,
    Scan,
    ScanFinding,
)
from src.api.schemas import BulkIdsRequest
from src.api.serializers import (
    source_payload,
    enum_value,
    finding_payload,
    image_payload,
    iso,
    paginate,
)
from src.api.routes._access import record_operator_event, require_role, severity_filter

router = APIRouter()


def _registry_url(configured: str, host: str) -> str:
    """An explicit URL, or the host over HTTP when REGISTRY_INSECURE is set (HTTPS otherwise)."""
    if configured.strip():
        return configured.strip().rstrip("/")
    return f"{'http' if get_settings().registry_insecure else 'https'}://{host.strip()}"


def _local_registry_base_url() -> str:
    settings = get_settings()
    return _registry_url(settings.local_registry_url, settings.local_registry_host)


def _local_registry_public_url() -> str:
    settings = get_settings()
    return _registry_url(settings.local_registry_public_url, settings.local_registry_public_host)


def _registry_json(path: str) -> dict:
    request = UrlRequest(f"{_local_registry_base_url()}{path}", headers={"accept": "application/json"})
    with urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def _registry_manifest_metadata(repository: str, tag: str) -> dict:
    path = f"/v2/{quote(repository, safe='/')}/manifests/{quote(tag, safe='')}"
    request = UrlRequest(
        f"{_local_registry_base_url()}{path}",
        headers={
            "accept": ", ".join(
                [
                    "application/vnd.oci.image.manifest.v1+json",
                    "application/vnd.docker.distribution.manifest.v2+json",
                    "application/vnd.docker.distribution.manifest.list.v2+json",
                ]
            )
        },
        method="HEAD",
    )
    with urlopen(request, timeout=10) as response:
        return {
            "digest": response.headers.get("Docker-Content-Digest"),
            "size": int(response.headers.get("Content-Length") or 0),
        }


@router.get("/images")
def image_inventory(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    search: str | None = Query(default=None, max_length=200),
    severity: str | None = Query(default=None),
) -> dict:
    severity_value = severity_filter(severity)
    with get_session() as session:
        query = session.query(Image).filter_by(active=True)
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
    findings_by_image: dict[int, list[ScanFinding]] = defaultdict(list)
    for finding in findings:
        findings_by_image[finding.image_id].append(finding)
    return paginate(
        [image_payload(image, findings_by_image[image.id], resolved_counts.get(image.id, 0)) for image in images],
        limit,
        offset,
        total,
    )


@router.get("/registry/inventory")
def registry_inventory(request: Request) -> dict:
    """Return the local registry catalog joined with scan and finding state."""
    require_role(request, "dashboard", "operator", "security-operator")
    try:
        catalog = _registry_json("/v2/_catalog?n=1000")
        repositories = [str(value) for value in catalog.get("repositories", [])]
        catalog_items: list[dict] = []
        for repository in repositories:
            tags_payload = _registry_json(f"/v2/{quote(repository, safe='/')}/tags/list")
            for tag in sorted(tags_payload.get("tags") or []):
                try:
                    manifest = _registry_manifest_metadata(repository, str(tag))
                except Exception as exc:
                    manifest = {"digest": None, "size": 0, "error": str(exc)[:200]}
                catalog_items.append({"repository": repository, "tag": str(tag), **manifest})
    except Exception as exc:
        raise HTTPException(status_code=503, detail="local_registry_unavailable") from exc

    registry_host = get_settings().local_registry_host.strip()
    with get_session() as session:
        images = session.query(Image).filter(Image.active.is_(True)).all()
        image_ids = [image.id for image in images]
        scans = (
            session.query(Scan)
            .filter(Scan.image_id.in_(image_ids))
            .order_by(Scan.started_at.desc(), Scan.id.desc())
            .all()
            if image_ids
            else []
        )
        findings = session.query(ScanFinding).filter(ScanFinding.image_id.in_(image_ids)).all() if image_ids else []

    scans_by_image: dict[int, Scan] = {}
    for scan in scans:
        scans_by_image.setdefault(scan.image_id, scan)
    findings_by_image: dict[int, list[ScanFinding]] = defaultdict(list)
    for finding in findings:
        findings_by_image[finding.image_id].append(finding)
    image_lookup: dict[tuple[str, str], Image] = {}
    for image in images:
        image_lookup[(f"{registry_host}/{image.repo_name}", image.tag)] = image
        image_lookup[(image.repo_name, image.tag)] = image

    tags: list[dict] = []
    for item in catalog_items:
        image = image_lookup.get((f"{registry_host}/{item['repository']}", item["tag"])) or image_lookup.get(
            (item["repository"], item["tag"])
        )
        image_findings = (
            [finding for finding in findings_by_image.get(image.id, []) if finding.resolved_at is None] if image else []
        )
        scan = scans_by_image.get(image.id) if image else None
        scan_status = enum_value(scan.status) if scan else None
        if scan_status in {"pending", "running"}:
            security_status = "scanning"
        elif scan_status == "failed":
            security_status = "scan_failed"
        elif scan is None:
            security_status = "not_scanned"
        elif image_findings:
            security_status = "issues_found"
        else:
            security_status = "clean"
        tags.append(
            {
                **item,
                "image_id": image.id if image else None,
                "scan_id": scan.scan_id if scan else None,
                "scan_status": scan_status,
                "last_scan_at": iso(image.last_scan_at) if image else None,
                "security_status": security_status,
                "open_findings": len(image_findings),
                "critical_count": sum(1 for finding in image_findings if enum_value(finding.severity) == "critical"),
                "high_count": sum(1 for finding in image_findings if enum_value(finding.severity) == "high"),
                "image_name": f"{registry_host}/{item['repository']}:{item['tag']}",
            }
        )

    counts = Counter(item["security_status"] for item in tags)
    return {
        "registry": {
            "host": get_settings().local_registry_public_host,
            "url": _local_registry_public_url(),
            "internal_host": registry_host,
            "reachable": True,
        },
        "repositories": repositories,
        "tags": tags,
        "summary": {
            "repositories": len(repositories),
            "tags": len(tags),
            "scanned": len(tags) - counts.get("not_scanned", 0),
            "not_scanned": counts.get("not_scanned", 0),
            "scanning": counts.get("scanning", 0),
            "issues_found": counts.get("issues_found", 0),
            "clean": counts.get("clean", 0),
        },
    }


@router.post("/images/bulk-archive")
def bulk_archive_images(payload: BulkIdsRequest, request: Request) -> dict:
    require_role(request, "operator", "security-operator")
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
    return {
        "image": {**image_payload(image, all_findings, resolved_count), "source": source_payload(image.source)},
        "findings": [finding_payload(finding) for finding in findings],
        "findings_page": paginate([finding_payload(finding) for finding in findings], limit, offset, total),
    }
