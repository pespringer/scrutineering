"""Data access layer (repositories) for Container Sentinel.

Each repository wraps a model and provides typed CRUD operations.
All methods accept a SQLAlchemy Session passed in by the caller so
transactions can span multiple repositories.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Sequence

from sqlalchemy import func, select, update, delete
from sqlalchemy.orm import Session, joinedload

from src.db.models import (
    AuditLog,
    AuditEventType,
    ComplianceReport,
    FindingSource,
    Image,
    ImageRegistry,
    PolicyEvaluation,
    Remediation,
    RemediationAction,
    RemediationStatus,
    Scan,
    ScanFinding,
    ScanStatus,
    Severity,
    SeveritySnapshot,
)


class ImageRepository:
    """CRUD for container images."""

    @staticmethod
    def create(
        session: Session,
        repo_name: str,
        tag: str = "latest",
        registry: ImageRegistry = ImageRegistry.DOCKER_HUB,
        digest: str | None = None,
        labels: dict | None = None,
    ) -> Image:
        image = Image(
            registry=registry,
            repo_name=repo_name,
            tag=tag,
            digest=digest,
            labels=labels or {},
        )
        session.add(image)
        session.flush()
        return image

    @staticmethod
    def get_by_id(session: Session, image_id: int) -> Image | None:
        return session.get(Image, image_id)

    @staticmethod
    def get_or_create(
        session: Session,
        repo_name: str,
        tag: str = "latest",
        registry: ImageRegistry = ImageRegistry.DOCKER_HUB,
        digest: str | None = None,
    ) -> tuple[Image, bool]:
        existing = session.execute(
            select(Image).where(
                Image.registry == registry,
                Image.repo_name == repo_name,
                Image.tag == tag,
            )
        ).scalar_one_or_none()
        if existing:
            return existing, False
        image = Image(
            registry=registry, tag=tag, repo_name=repo_name, digest=digest
        )
        session.add(image)
        session.flush()
        return image, True

    @staticmethod
    def list_active(session: Session, limit: int = 100, offset: int = 0) -> Sequence[Image]:
        return session.execute(
            select(Image)
            .where(Image.active.is_(True))
            .order_by(Image.last_scan_at.desc().nulls_last())
            .limit(limit)
            .offset(offset)
        ).scalars().all()

    @staticmethod
    def deactivate(session: Session, image_id: int) -> None:
        session.execute(
            update(Image).where(Image.id == image_id).values(active=False)
        )

    @staticmethod
    def search(session: Session, query: str) -> Sequence[Image]:
        pattern = f"%{query}%"
        return session.execute(
            select(Image).where(
                Image.repo_name.ilike(pattern)
                | Image.tag.ilike(pattern)
            ).limit(50)
        ).scalars().all()


class ScanRepository:
    """CRUD for scan executions."""

    @staticmethod
    def create(
        session: Session,
        image_id: int,
        scan_id: str,
        scheduler_type: str | None = "manual",
    ) -> Scan:
        scan = Scan(
            image_id=image_id,
            scan_id=scan_id,
            scheduler_type=scheduler_type,
            status=ScanStatus.PENDING,
        )
        session.add(scan)
        session.flush()
        return scan

    @staticmethod
    def get_by_scan_id(session: Session, scan_id: str) -> Scan | None:
        return session.execute(
            select(Scan).where(Scan.scan_id == scan_id)
        ).scalar_one_or_none()

    @staticmethod
    def mark_running(session: Session, scan_db_id: int, scan_id: str) -> None:
        session.execute(
            update(Scan)
            .where(Scan.id == scan_db_id)
            .values(status=ScanStatus.RUNNING)
        )

    @staticmethod
    def mark_completed(
        session: Session,
        scan_db_id: int,
        total: int,
        critical: int,
        high: int,
        medium: int,
        low: int,
    ) -> None:
        session.execute(
            update(Scan)
            .where(Scan.id == scan_db_id)
            .values(
                status=ScanStatus.COMPLETED,
                completed_at=func.now(),
                total_findings=total,
                critical_count=critical,
                high_count=high,
                medium_count=medium,
                low_count=low,
            )
        )

    @staticmethod
    def mark_failed(session: Session, scan_db_id: int, error: str) -> None:
        session.execute(
            update(Scan)
            .where(Scan.id == scan_db_id)
            .values(
                status=ScanStatus.FAILED,
                completed_at=func.now(),
                error_message=error,
            )
        )

    @staticmethod
    def list_by_image(
        session: Session, image_id: int, limit: int = 20
    ) -> Sequence[Scan]:
        return session.execute(
            select(Scan)
            .where(Scan.image_id == image_id)
            .order_by(Scan.started_at.desc())
            .limit(limit)
        ).scalars().all()


class FindingRepository:
    """CRUD for vulnerability findings."""

    @staticmethod
    def upsert_finding(
        session: Session,
        image_id: int,
        scan_id: str | None,
        fingerprint: str,
        package_name: str,
        cve_id: str | None = None,
        title: str = "",
        description: str | None = None,
        severity: Severity | None = None,
        source: FindingSource = FindingSource.TRIVY,
        package_version: str | None = None,
        package_type: str | None = None,
        fixed_version: str | None = None,
        fix_available: bool = False,
        scanner_version: str | None = None,
    ) -> ScanFinding:
        existing = session.execute(
            select(ScanFinding).where(
                ScanFinding.fingerprint == fingerprint,
                ScanFinding.image_id == image_id,
            )
        ).scalar_one_or_none()

        if existing:
            existing.last_seen = func.now()
            existing.scan_id = scan_id
            existing.severity = severity
            existing.title = title
            existing.description = description
            if fixed_version:
                existing.fixed_version = fixed_version
            if fix_available:
                existing.fix_available = True
            return existing

        finding = ScanFinding(
            scan_id=scan_id,
            image_id=image_id,
            fingerprint=fingerprint,
            package_name=package_name,
            package_version=package_version,
            package_type=package_type,
            cve_id=cve_id,
            title=title,
            description=description,
            severity=severity,
            source=source,
            fixed_version=fixed_version,
            fix_available=fix_available,
            scanner_version=scanner_version,
        )
        session.add(finding)
        session.flush()
        return finding

    @staticmethod
    def list_by_image(
        session: Session,
        image_id: int,
        severity: Severity | None = None,
        remediated: bool | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Sequence[ScanFinding]:
        q = select(ScanFinding).where(ScanFinding.image_id == image_id)
        if severity is not None:
            q = q.where(ScanFinding.severity == severity)
        if remediated is not None:
            q = q.where(ScanFinding.remediated == remediated)
        q = q.order_by(
            func.case(
                (ScanFinding.severity == Severity.CRITICAL, 1),
                (ScanFinding.severity == Severity.HIGH, 2),
                (ScanFinding.severity == Severity.MEDIUM, 3),
                (ScanFinding.severity == Severity.LOW, 4),
                else_=5,
            ),
            ScanFinding.first_seen.desc(),
        ).limit(limit).offset(offset)
        return session.execute(q).scalars().all()

    @staticmethod
    def count_by_severity(
        session: Session, image_id: int, remediated: bool = False
    ) -> dict[str, int]:
        stmt = (
            select(
                ScanFinding.severity,
                func.count(ScanFinding.id),
            )
            .where(
                ScanFinding.image_id == image_id,
                ScanFinding.remediated == remediated,
            )
            .group_by(ScanFinding.severity)
        )
        rows = session.execute(stmt).all()
        counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
        for sev, count in rows:
            if sev:
                counts[sev.value] = count
        return counts

    @staticmethod
    def mark_remediated(session: Session, finding_ids: list[int]) -> int:
        result = session.execute(
            update(ScanFinding)
            .where(ScanFinding.id.in_(finding_ids))
            .values(remediated=True)
        )
        return result.rowcount

    @staticmethod
    def list_open_criticals(session: Session) -> Sequence[ScanFinding]:
        return session.execute(
            select(ScanFinding)
            .options(joinedload(ScanFinding.image))
            .where(
                ScanFinding.remediated.is_(False),
                ScanFinding.severity.in_(
                    [Severity.CRITICAL, Severity.HIGH]
                ),
            )
            .order_by(ScanFinding.first_seen.desc())
            .limit(50)
        ).scalars().all()


class RemediationRepository:
    """CRUD for remediation workflows."""

    @staticmethod
    def create(
        session: Session,
        image_id: int,
        scan_id: str | None = None,
        finding_count: int = 0,
        target_severities: dict | None = None,
    ) -> Remediation:
        rem = Remediation(
            image_id=image_id,
            scan_id=scan_id,
            finding_count=finding_count,
            target_severities=target_severities or {},
        )
        session.add(rem)
        session.flush()
        return rem

    @staticmethod
    def update_status(
        session: Session,
        remediation_id: int,
        status,  # RemediationStatus enum value
        **kw,
    ) -> None:
        values: dict = {"status": status}
        if status == RemediationStatus.STARTED and "started_at" not in kw:
            values["started_at"] = func.now()
        if status in (RemediationStatus.COMPLETED, RemediationStatus.FAILED):
            values["completed_at"] = func.now()
        values.update({k: v for k, v in kw.items() if k in values or k not in ("status",)})
        session.execute(
            update(Remediation)
            .where(Remediation.id == remediation_id)
            .values(**{k: v for k, v in values.items() if v is not None})
        )

    @staticmethod
    def add_action(
        session: Session,
        remediation_id: int,
        action_type,
        file_path: str | None = None,
        before_value: str | None = None,
        after_value: str | None = None,
        success: bool = False,
        detail: dict | None = None,
    ) -> RemediationAction:
        action = RemediationAction(
            remediation_id=remediation_id,
            action_type=action_type,
            file_path=file_path,
            before_value=before_value,
            after_value=after_value,
            success=success,
            detail=detail or {},
        )
        session.add(action)
        session.flush()
        return action

    @staticmethod
    def get_by_id(session: Session, remediation_id: int) -> Remediation | None:
        return session.execute(
            select(Remediation)
            .options(joinedload(Remediation.actions))
            .where(Remediation.id == remediation_id)
        ).unique().scalar_one_or_none()

    @staticmethod
    def list_by_image(
        session: Session, image_id: int, limit: int = 20
    ) -> Sequence[Remediation]:
        return session.execute(
            select(Remediation)
            .where(Remediation.image_id == image_id)
            .order_by(Remediation.created_at.desc())
            .limit(limit)
        ).scalars().all()

    @staticmethod
    def list_in_progress(session: Session) -> Sequence[Remediation]:
        return session.execute(
            select(Remediation)
            .where(
                Remediation.status.in_(
                    [RemediationStatus.PENDING, RemediationStatus.ANALYZING,
                     RemediationStatus.PATCHING, RemediationStatus.BUILDING,
                     RemediationStatus.VERIFYING]
                )
            )
            .order_by(Remediation.created_at)
        ).scalars().all()


class AuditLogRepository:
    """Append-only audit log writes."""

    @staticmethod
    def record(
        session: Session,
        event_type: AuditEventType,
        detail: dict | None = None,
        entity_type: str | None = None,
        entity_id: str | None = None,
        image_id: int | None = None,
        actor: str | None = None,
        actor_kind: str | None = None,
    ) -> AuditLog:
        entry = AuditLog(
            event_type=event_type,
            detail=detail or {},
            entity_type=entity_type,
            entity_id=entity_id,
            image_id=image_id,
            actor=actor,
            actor_kind=actor_kind,
        )
        session.add(entry)
        session.flush()
        return entry
