"""The bundled registry: its catalog joined with scan state, what one tag holds, and deleting tags."""

from __future__ import annotations

import logging
from collections import Counter, defaultdict

from fastapi import APIRouter, HTTPException, Query, Request

from src.api.roles import allowed, require_action
from src.api.routes._access import record_operator_event
from src.api.schemas import RegistryDeleteRequest, RegistryTagItem
from src.api.serializers import enum_value, iso
from src.config import get_settings
from src.db.connection import get_session
from src.db.models import AuditEventType, Image, Remediation, Scan, ScanFinding
from src.scan.registry_catalog import (
    CatalogTag,
    RegistryClient,
    RegistryError,
    catalog,
    registry_url,
    stored_bytes,
    tag_detail,
    valid_repository,
    valid_tag,
)
from src.scan.registry_delete import CANDIDATE_TAG, Refused, Tag, delete_tag

logger = logging.getLogger(__name__)
router = APIRouter()

NO_IMAGE = {"size": None, "platforms": [], "attestations": 0}


def public_registry_url() -> str:
    settings = get_settings()
    return registry_url(settings.local_registry_public_url, settings.local_registry_public_host)


def _image_name(item: CatalogTag) -> str:
    return f"{get_settings().local_registry_host.strip()}/{item.repository}:{item.tag}"


def _security_status(status: str | None, open_findings: int) -> str:
    if status in {"pending", "running"}:
        return "scanning"
    if status == "failed":
        return "scan_failed"
    if status is None:
        return "not_scanned"
    return "issues_found" if open_findings else "clean"


def _scan_state(session, tags: list[CatalogTag]) -> dict[str, dict]:
    """Scan and finding state by full image name, host included: `team/app` on Docker Hub is another image."""
    host = get_settings().local_registry_host.strip()
    repositories = {f"{host}/{item.repository}" for item in tags}
    # Columns, not entities: whole rows load relationships and large documents this doesn't need.
    images = (
        session.query(Image.id, Image.repo_name, Image.tag, Image.last_scan_at)
        .filter(Image.active.is_(True), Image.repo_name.in_(repositories))
        .all()
    )
    image_ids = [image.id for image in images]
    latest: dict = {}
    scans = session.query(Scan.image_id, Scan.scan_id, Scan.status).filter(Scan.image_id.in_(image_ids))
    for scan in scans.order_by(Scan.started_at.desc(), Scan.id.desc()):
        latest.setdefault(scan.image_id, scan)
    severities: dict[int, Counter] = defaultdict(Counter)
    for image_id, severity in session.query(ScanFinding.image_id, ScanFinding.severity).filter(
        ScanFinding.image_id.in_(image_ids), ScanFinding.resolved_at.is_(None)
    ):
        severities[image_id][enum_value(severity)] += 1
    state = {}
    for image in images:
        scan, counts = latest.get(image.id), severities[image.id]
        status = enum_value(scan.status) if scan else None
        state[f"{image.repo_name}:{image.tag}"] = {
            "image_id": image.id,
            "scan_id": scan.scan_id if scan else None,
            "scan_status": status,
            "last_scan_at": iso(image.last_scan_at),
            "security_status": _security_status(status, counts.total()),
            "open_findings": counts.total(),
            "critical_count": counts["critical"],
            "high_count": counts["high"],
        }
    return state


UNTRACKED = {
    "image_id": None,
    "scan_id": None,
    "scan_status": None,
    "last_scan_at": None,
    "security_status": "not_scanned",
    "open_findings": 0,
    "critical_count": 0,
    "high_count": 0,
}


def _candidates(session, tags: list[CatalogTag], show: bool) -> dict[str, dict]:
    """The remediation each candidate tag belongs to, by image name.

    The tag's number alone isn't proof: the registry outlives database resets, so the recorded reference
    and digest must match too. Remediations are shown only to a caller who may see them.
    """
    numbers = {_image_name(item): int(match.group(1)) for item in tags if (match := CANDIDATE_TAG.fullmatch(item.tag))}
    columns = (Remediation.id, Remediation.status, Remediation.candidate_image, Remediation.candidate_digest)
    rows = session.query(*columns).filter(Remediation.id.in_(set(numbers.values()))).all() if show else []
    remediations = {row.id: row for row in rows}
    digests = {_image_name(item): item.digest for item in tags}
    found = {}
    for name, number in numbers.items():
        row = remediations.get(number)
        matches = row is not None and row.candidate_image == name and row.candidate_digest == digests[name]
        found[name] = {
            "remediation_id": row.id if matches else None,
            "status": enum_value(row.status) if matches else None,
        }
    return found


def _tag_payload(item: CatalogTag, shared: Counter, state: dict, candidates: dict) -> dict:
    name = _image_name(item)
    return {
        "repository": item.repository,
        "tag": item.tag,
        "image_name": name,
        "digest": item.digest,
        "error": item.error,
        **(item.summary.payload() if item.summary else NO_IMAGE),
        # Other tags in the repository that point to the same image.
        "shared_count": shared[(item.repository, item.digest)] - 1 if item.digest else 0,
        "candidate": candidates.get(name),
        **state.get(name, UNTRACKED),
    }


@router.get("/registry/inventory")
def registry_inventory(request: Request) -> dict:
    """The local registry's catalog joined with scan and finding state."""
    require_action(request, "registry.view")
    try:
        tags = catalog(RegistryClient.local())
    except RegistryError as error:
        raise HTTPException(status_code=503, detail="local_registry_unavailable") from error
    with get_session() as session:
        state = _scan_state(session, tags)
        show = allowed(getattr(request.state, "principal_roles", []), "remediations.view")
        candidates = _candidates(session, tags, show)

    by_repository: dict[str, list[CatalogTag]] = defaultdict(list)
    for item in tags:
        by_repository[item.repository].append(item)
    shared = Counter((item.repository, item.digest) for item in tags)
    payloads = [_tag_payload(item, shared, state, candidates) for item in tags]
    counts = Counter(item["security_status"] for item in payloads)
    settings = get_settings()
    return {
        "registry": {
            "host": settings.local_registry_public_host,
            "url": public_registry_url(),
            "internal_host": settings.local_registry_host.strip(),
            "reachable": True,
        },
        "repositories": [
            {"name": name, "tags": len(items), "stored_bytes": stored_bytes(items)}
            for name, items in sorted(by_repository.items())
        ],
        "tags": payloads,
        "summary": {
            "repositories": len(by_repository),
            "tags": len(tags),
            "stored_bytes": stored_bytes(tags),
            "scanned": len(tags) - counts["not_scanned"],
            "not_scanned": counts["not_scanned"],
            "scanning": counts["scanning"],
            "issues_found": counts["issues_found"],
            "clean": counts["clean"],
        },
    }


@router.get("/registry/tags/detail")
def registry_tag_detail(
    request: Request,
    repository: str = Query(max_length=255),
    tag: str = Query(max_length=128),
) -> dict:
    """What one tag holds, per platform: layers, build date, labels, settings and build history."""
    require_action(request, "registry.view")
    if not valid_repository(repository) or not valid_tag(tag):
        raise HTTPException(status_code=400, detail="invalid_image_reference")
    try:
        return tag_detail(RegistryClient.local(), repository, tag)
    except RegistryError as error:
        if error.status == 404:
            raise HTTPException(status_code=404, detail="tag_not_found") from error
        raise HTTPException(status_code=502, detail=f"This image can't be read: {error}.") from error


def _delete(request: Request, client: RegistryClient, item: RegistryTagItem) -> dict:
    """Delete one tag in its own transaction, so a refusal or failure doesn't undo the others."""
    tag = Tag(item.repository, item.tag)
    result = {"repository": item.repository, "tag": item.tag}
    removed = False
    try:
        with get_session() as session:
            archived = delete_tag(session, client, tag, item.digest)
            removed = True
            # Last, so the audit chain's lock isn't held during the registry call.
            record_operator_event(
                session,
                request,
                AuditEventType.CONFIG_CHANGED,
                item.digest,
                {"action": "delete_registry_tag", "image": tag.name, "archived_image_ids": archived},
                entity_type="registry_tag",
            )
    except Refused as refused:
        return {**result, "deleted": False, "code": refused.code, "reason": refused.reason}
    except Exception:
        if not removed:
            logger.exception("could not delete %s", tag.name)
            return {**result, "deleted": False, "code": "delete_failed", "reason": "It couldn't be deleted."}
        logger.exception("deleted %s (%s) from the registry, but could not record it", tag.name, item.digest)
        reason = "It was deleted, but that couldn't be recorded. See the API log."
        return {**result, "deleted": True, "code": "delete_not_recorded", "reason": reason}
    return {**result, "deleted": True, "code": None, "reason": None}


@router.post("/registry/tags/delete")
def delete_registry_tags(payload: RegistryDeleteRequest, request: Request) -> dict:
    """Delete tags, one at a time. Each has its own result; a tag something needs is refused."""
    require_action(request, "registry.delete")
    client = RegistryClient.local()
    results = [_delete(request, client, item) for item in payload.items]
    return {"results": results, "deleted": sum(1 for result in results if result["deleted"])}
