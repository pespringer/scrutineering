"""Runtime discovery: find the images of running containers, record them, and scan the ones that need it.

See docs/design/runtime-discovery.md. A run lists running containers, keeps the images it can scan
(pulled from a registry), marks them as seen running, and queues only those never scanned or
scanned before the cooldown, with no scan already pending or running. Its result goes to Redis for
the system status panel; a runtime that can't be reached is reported as an error, not as "nothing
running". On Docker, a run also records each container of a scannable image (src/scan/deployments.py).
"""

from __future__ import annotations

import fnmatch
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable

logger = logging.getLogger(__name__)

OPT_OUT_LABEL = "scrutineering.scan"
IMAGE_ID = re.compile(r"(sha256:)?[0-9a-f]{12,64}")
STATUS_KEY = "scrutineering:runtime-discovery"
STATUS_TTL_SECONDS = 3600
# An image counts as running if a discovery run saw it within two runs (beat runs every 15 minutes).
RUNNING_WINDOW = timedelta(minutes=30)


def running_since(now: datetime | None = None) -> datetime:
    """The oldest `last_seen_running_at` that still counts as running."""
    return (now or datetime.now(timezone.utc).replace(tzinfo=None)) - RUNNING_WINDOW


def _labels(labels: Any) -> dict[str, str]:
    if isinstance(labels, str):
        return dict(item.split("=", 1) for item in labels.split(",") if "=" in item)
    return labels if isinstance(labels, dict) else {}


def _labels_match(labels: Any, expression: str | None) -> bool:
    if not expression:
        return True
    key, separator, expected = expression.partition("=")
    if not separator or not key:
        return False
    return _labels(labels).get(key) == expected


def select_runtime_images(
    containers: list[dict[str, Any]],
    *,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    exclude_containers: list[str] | None = None,
    include_label: str | None = None,
    limit: int | None = None,
) -> list[str]:
    """Return stable, unique image references selected from running containers.

    A container labelled `scrutineering.scan=false` is always skipped.
    """
    if limit is not None and limit < 1:
        raise ValueError("runtime discovery limit must be positive")
    include, exclude, exclude_containers = include or [], exclude or [], exclude_containers or []
    selected: list[str] = []
    seen: set[str] = set()
    for container in containers:
        image = str(container.get("image") or "").strip()
        name = str(container.get("names") or container.get("id") or "").strip()
        labels = container.get("labels")
        if not image or not _labels_match(labels, include_label):
            continue
        if _labels(labels).get(OPT_OUT_LABEL, "").strip().lower() == "false":
            continue
        if exclude_containers and any(fnmatch.fnmatchcase(name, pattern) for pattern in exclude_containers):
            continue
        if include and not any(fnmatch.fnmatchcase(image, pattern) for pattern in include):
            continue
        if exclude and any(fnmatch.fnmatchcase(image, pattern) for pattern in exclude):
            continue
        if image not in seen:
            seen.add(image)
            selected.append(image)
        if limit is not None and len(selected) >= limit:
            break
    return selected


@dataclass
class Classified:
    """Running images split by whether the scanners can pull them."""

    scannable: list[str] = field(default_factory=list)
    local_only: int = 0  # built on the host: no registry digest
    id_only: int = 0  # the container shows only an image ID


async def classify(
    images: list[str],
    repo_digests: Callable[[str], Awaitable[list[str] | None]] | None,
    in_registry: Callable[[str], bool | None] | None = None,
    known: set[str] | None = None,
) -> Classified:
    """Keep the images the scanners can pull.

    An image is skipped as local-only when Docker has no registry digest for it (the classic image
    store), or when its registry says it doesn't exist or refuses access. Docker's containerd image
    store gives local builds a digest too, so the registry is the reliable check. Images already
    tracked (`known`) skip the registry check; a registry that can't be reached keeps the image, and
    the scan decides. Without a digest lookup (containerd), named images are kept.
    """
    result = Classified()
    known = known or set()
    for image in images:
        if IMAGE_ID.fullmatch(image):
            result.id_only += 1
        elif repo_digests is not None and not await repo_digests(image):
            result.local_only += 1
        elif image not in known and in_registry is not None and in_registry(image) is False:
            result.local_only += 1
        else:
            result.scannable.append(image)
    return result


def in_registry(reference: str) -> bool | None:
    """Whether the image's registry resolves it with the worker's credentials, as a scan would.

    False when the registry says it doesn't exist or refuses access (the scanners couldn't pull it);
    None when the registry couldn't be asked.
    """
    from urllib.error import HTTPError

    from src.scan.image_identity import parse_image_reference
    from src.scan.registry import credentials_for_host, resolve_digest
    from src.scan.settings import ScannerSettings

    try:
        identity = parse_image_reference(reference)
        insecure = ScannerSettings.from_env().insecure_host(identity.host)
        credentials = credentials_for_host(identity.host)
        resolve_digest(identity, credentials=credentials, scheme="http" if insecure else "https")
    except HTTPError as error:
        return False if error.code in (401, 403, 404) else None
    except PermissionError:
        return False
    except Exception:  # noqa: BLE001 - unreachable or unexpected: let the scan decide
        return None
    return True


def known_images(references: list[str]) -> set[str]:
    """The references with a completed or partial scan: proof the scanners can pull them."""
    from src.db.connection import get_session
    from src.db.models import Image, Scan, ScanStatus
    from src.scan.records import scan_identity

    found = set()
    with get_session() as session:
        for reference in references:
            try:
                identity = scan_identity(reference)
            except ValueError:
                continue
            scanned = (
                session.query(Scan.id)
                .join(Image, Scan.image_id == Image.id)
                .filter(
                    Image.registry_name == identity.registry,
                    Image.repo_name == identity.repo_name,
                    Image.tag == identity.tag,
                    Scan.status.in_([ScanStatus.COMPLETED.value, ScanStatus.PARTIAL.value]),
                )
                .first()
            )
            if scanned:
                found.add(reference)
    return found


async def discover_runtime_containers(
    *,
    use_containerd: bool = False,
    docker_bin: str = "docker",
    ctr_bin: str = "ctr",
    containerd_namespace: str = "default",
) -> tuple[list[dict[str, Any]], Any]:
    """Running containers, and the Docker collector for digest lookups and inspection (None on containerd).

    Raises RuntimeUnavailable when the runtime can't be listed.
    """
    if use_containerd:
        from src.scan.discovery import ContainerdCollector

        collector = ContainerdCollector(ctr_bin=ctr_bin, namespace=containerd_namespace)
        containers = await collector.list_running_containers()
        for container in containers:
            if not container.get("image"):
                info = await collector.get_container_info(container["id"])
                if info:
                    container["image"] = info.get("image") or info.get("runtime_image") or ""
        return containers, None
    from src.scan.discovery import DockerRuntimeCollector

    docker = DockerRuntimeCollector(docker_bin=docker_bin)
    return await docker.list_running_containers(), docker


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def record_and_select(images: list[str], *, cooldown_seconds: int, now: datetime) -> list[str]:
    """Mark each image as seen running, and return the ones due for a scan, oldest scan first."""
    from src.db.connection import get_session
    from src.db.models import Scan, ScanStatus
    from src.scan.records import get_or_create_image, scan_identity
    from src.scan.reliability import ScanCooldown, cooldown_active

    policy = ScanCooldown(cooldown_seconds)
    aware_now = now.replace(tzinfo=timezone.utc)  # cooldown_active compares in UTC
    candidates = []
    with get_session() as session:
        for reference in images:
            try:
                image = get_or_create_image(session, scan_identity(reference))
            except ValueError:
                logger.warning("runtime discovery skipped an image reference it could not parse: %r", reference)
                continue
            image.last_seen_running_at = now
            candidates.append((reference, image.id, image.last_scan_at))
        session.flush()
        busy = {
            image_id
            for (image_id,) in session.query(Scan.image_id)
            .filter(
                Scan.image_id.in_([image_id for _, image_id, _ in candidates]),
                Scan.status.in_([ScanStatus.PENDING.value, ScanStatus.RUNNING.value]),
            )
            .all()
        }
    due = [
        (last_scan_at or datetime.min, reference)
        for reference, image_id, last_scan_at in candidates
        if image_id not in busy and not cooldown_active(last_scan_at, policy=policy, now=aware_now)
    ]
    return [reference for _, reference in sorted(due)]


def run_discovery(settings, *, queue: Callable[[str], object], collect=None, now: datetime | None = None) -> dict:
    """One discovery run. Returns, and stores, the status shown in the system panel."""
    import asyncio

    from src.scan import deployments
    from src.scan.discovery._process import RuntimeUnavailable

    now = now or _now()
    status: dict[str, Any] = {"status": "ok", "checked_at": now.isoformat(timespec="seconds") + "Z", "error": None}
    if not settings.scan_runtime_discovery_enabled:
        status["status"] = "disabled"
        save_status(status, settings.redis_url)
        return status

    async def default_collect():
        containers, docker = await discover_runtime_containers(
            use_containerd=settings.scan_runtime_use_containerd,
            docker_bin=settings.scan_runtime_docker_bin,
            ctr_bin=settings.scan_runtime_ctr_bin,
            containerd_namespace=settings.scan_runtime_containerd_namespace,
        )
        images = select_runtime_images(
            containers,
            include=settings.scan_runtime_include_images,
            exclude=settings.scan_runtime_exclude_images,
            exclude_containers=settings.scan_runtime_exclude_containers,
            include_label=settings.scan_runtime_include_label,
        )
        repo_digests = docker.repo_digests if docker else None
        classified = await classify(images, repo_digests, in_registry, known_images(images))
        observed = None
        if docker:
            observed = await deployments.observe(
                containers, classified.scannable, docker.inspect_containers, docker.repo_digests
            )
        return containers, classified, observed

    try:
        containers, classified, observed = asyncio.run((collect or default_collect)())
    except RuntimeUnavailable as exc:
        logger.warning("runtime discovery could not list containers: %s", exc)
        status.update(status="error", error=str(exc))
        save_status(status, settings.redis_url)
        return status

    due = record_and_select(classified.scannable, cooldown_seconds=settings.scan_cooldown_seconds, now=now)
    if observed is not None:
        listed = {str(container.get("id")) for container in containers if container.get("id")}
        status["deployments"] = deployments.record(observed, listed, now=now)
    queued = 0
    for image in due[: settings.scan_runtime_max_images]:
        try:
            queue(image)
            queued += 1
        except Exception:
            logger.exception("runtime discovery could not queue a scan of %s", image)
    status.update(
        containers=len(containers),
        running_images=len(classified.scannable),
        local_only=classified.local_only,
        id_only=classified.id_only,
        queued=queued,
    )
    logger.info("runtime discovery: %s", json.dumps(status, sort_keys=True))
    save_status(status, settings.redis_url)
    return status


def _redis(url: str):
    import redis

    return redis.Redis.from_url(url, socket_timeout=2, socket_connect_timeout=2)


def save_status(status: dict, redis_url: str) -> None:
    """Keep the last run's result for an hour. It's status, not history, so there is no table."""
    try:
        _redis(redis_url).set(STATUS_KEY, json.dumps(status), ex=STATUS_TTL_SECONDS)
    except Exception as exc:  # noqa: BLE001 - the status panel says "not reported" instead
        logger.warning("could not save the runtime discovery status: %s", exc)


def load_status(redis_url: str) -> dict | None:
    """The last run's result, or None if there is none within the hour or Redis is unreachable."""
    try:
        raw = _redis(redis_url).get(STATUS_KEY)
    except Exception:  # noqa: BLE001
        return None
    try:
        return json.loads(raw) if raw else None
    except (TypeError, ValueError):
        return None
