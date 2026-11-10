"""Backward-compatible scan persistence utilities.

These helpers wrap the newer repository layer so existing scan
pipeline code (Celery tasks, scanner wrappers) can keep using a
simple function-call interface while the data goes through the
canonical models in src.db.models.
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from src.db.models import (
    Base,
    FindingSource,
    Image,
    ImageRegistry,
    ScanFinding,
    Severity,
)
from src.db.config import get_database_url
from src.scan.image_identity import parse_image_reference

DATABASE_URL = get_database_url("SCAN_DATABASE_URL", "DATABASE_URL")

_sync_url = DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://", 1) if DATABASE_URL.startswith("postgresql://") else DATABASE_URL

engine_options = {"pool_pre_ping": True}
if not _sync_url.startswith("sqlite"):
    engine_options.update(pool_size=5, max_overflow=10)

engine = create_engine(_sync_url, **engine_options)


def init_db():
    """Create all tables."""
    Base.metadata.create_all(engine)


def get_session():
    """Return a plain Session (caller manages commit/rollback/close)."""
    return Session(engine)


def _parse_image_name(image_name: str) -> tuple[ImageRegistry, str, str]:
    """Best-effort parse of a Docker image name into registry/repo/tag.

    Examples:
        'library/nginx:latest' -> (DOCKER_HUB, 'library/nginx', 'latest')
        'ghcr.io/user/app:v1'  -> (GHCR, 'user/app', 'v1')
        'myregistry:5000/foo'  -> (OTHER, 'myregistry:5000/foo', 'latest')
    """
    identity = parse_image_reference(image_name)
    return identity.registry, identity.repo_name, identity.tag


def _make_fingerprint(cve_id: str, package_name: str,
                      package_version: str) -> str:
    """Deterministic fingerprint for deduplication across scanners."""
    raw = f"{cve_id or ''}:{package_name}:{package_version or ''}"
    return hashlib.sha256(raw.encode()).hexdigest()[:64]


def persist_findings(
    scan_id: str,
    image_name: str,
    deduped_findings: list[dict],
    source_name: str,
) -> int:
    """Persist deduplicated scan findings to the database.

    For each finding:
    - Resolve or create the Image record from image_name
    - If fingerprint already exists for that image: update last_seen
    - Otherwise: insert new finding

    Returns count of findings persisted/updated.
    """
    from src.db.connection import get_session as get_db_session

    now = datetime.now(timezone.utc)
    identity = parse_image_reference(image_name)
    registry, repo, tag = identity.registry, identity.repo_name, identity.tag
    count = 0

    with get_db_session() as session:
        # Resolve or create image
        img_q = select(Image).where(
            Image.registry_name == registry,
            Image.repo_name == repo,
            Image.tag == tag,
        )
        image = session.execute(img_q).scalar_one_or_none()
        if not image:
            image = Image(
                registry_name=registry,
                repo_name=repo,
                tag=tag,
                digest=identity.digest,
            )
            session.add(image)
            session.flush()
        elif identity.digest and image.digest != identity.digest:
            image.digest = identity.digest

        for finding in deduped_findings:
            severity_str = finding.get("severity")
            severity_enum = None
            if severity_str:
                try:
                    severity_enum = Severity(severity_str)
                except ValueError:
                    severity_enum = Severity.UNKNOWN

            cve_id = finding.get("cve_id")
            pkg_name = finding["package_name"]
            pkg_ver = finding.get("package_version", "")
            fp = _make_fingerprint(cve_id or "", pkg_name, pkg_ver or "")

            existing = session.execute(
                select(ScanFinding).where(
                    ScanFinding.fingerprint == fp,
                    ScanFinding.image_id == image.id,
                )
            ).scalar_one_or_none()

            if existing:
                existing.last_seen = now
                if severity_enum:
                    existing.severity = severity_enum
                existing.title = finding.get("title", existing.title)
                if finding.get("fixed_version"):
                    existing.fixed_version = finding["fixed_version"]
                    existing.fix_available = True
            else:
                new_finding = ScanFinding(
                    scan_id=scan_id,
                    image_id=image.id,
                    fingerprint=fp,
                    package_name=pkg_name,
                    package_version=finding.get("package_version"),
                    package_type=finding.get("package_type"),
                    cve_id=cve_id,
                    title=finding.get("title", ""),
                    description=finding.get("description"),
                    severity=severity_enum,
                    source=FindingSource(source_name),
                    fixed_version=finding.get("fixed_version"),
                    fix_available=bool(finding.get("fixed_version")),
                )
                session.add(new_finding)

            count += 1

    return count
