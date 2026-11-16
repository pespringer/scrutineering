"""Complete database schema for Container Sentinel.

Tables:
  - scans:              Individual scan runs (per image per execution)
  - images:             Tracked container images and metadata
  - scan_findings:      Normalized vulnerability findings (from both scanners)
  - raw_scan_results:   Raw JSON output from scanners for audit/forensics
  - severity_snapshots: Daily severity count snapshots for trend tracking
  - security_policies:  Configurable security policies and rules
  - policy_evaluations: Log of policy evaluations against scans
  - remediations:       Remediation attempts and their outcomes
  - remediation_actions: Individual actions within a remediation (e.g., base image bump)
  - compliance_reports: Generated compliance report metadata
  - audit_log:          Append-only audit log for all security events
  - container_runtime:  Runtime behavior monitoring data
"""

from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
    CheckConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.sql import func


# -- Base ------------------------------------------------------------------- #

# BIGINT on Postgres; INTEGER on SQLite, where only INTEGER primary keys auto-increment.
PrimaryKey = BigInteger().with_variant(Integer(), "sqlite")


class Base(DeclarativeBase):
    """Declarative base — all models inherit from this."""

    pass


# -- Enums ------------------------------------------------------------------ #


class Severity(str, enum.Enum):
    """Standardised severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class FindingSource(str, enum.Enum):
    """Scanner that produced the finding."""

    TRIVY = "trivy"
    GRYPE = "grype"


class ImageRegistry(str, enum.Enum):
    """Known container registries."""

    DOCKER_HUB = "dockerhub"
    GCR = "gcr"
    ECR = "ecr"
    GHCR = "ghcr"
    GITLAB = "gitlab"
    HARBOR = "harbor"
    QUAY = "quay"
    OTHER = "other"


class RemediationStatus(str, enum.Enum):
    """Lifecycle states of a remediation effort."""

    PENDING = "pending"
    ANALYZING = "analyzing"
    PATCHING = "patching"
    BUILDING = "building"
    VERIFYING = "verifying"
    PR_OPENED = "pr_opened"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    REQUIRES_REVIEW = "requires_review"


class RemediationActionType(str, enum.Enum):
    """Types of remediation actions."""

    BASE_IMAGE_BUMP = "base_image_bump"
    DEPENDENCY_UPDATE = "dependency_update"
    OS_PACKAGE_UPGRADE = "os_package_upgrade"
    CONFIG_CHANGE = "config_change"
    PACKAGE_REMOVAL = "package_removal"
    CUSTOM = "custom"


class AuditEventType(str, enum.Enum):
    """Types of audit events."""

    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    SCAN_CANCELLED = "scan_cancelled"
    FINDING_CREATED = "finding_created"
    FINDING_CLOSED = "finding_closed"
    REMEDIATION_STARTED = "remediation_started"
    REMEDIATION_COMPLETED = "remediation_completed"
    REMEDIATION_FAILED = "remediation_failed"
    POLICY_CREATED = "policy_created"
    POLICY_UPDATED = "policy_updated"
    POLICY_VIOLATED = "policy_violated"
    COMPLIANCE_REPORT_GENERATED = "compliance_report_generated"
    CONFIG_CHANGED = "config_changed"
    USER_LOGIN = "user_login"
    SYSTEM_ERROR = "system_error"


class ScanStatus(str, enum.Enum):
    """Status of an individual image scan."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


def _enum_values(enum_type):
    """Persist enum values (the lowercase database contract), not member names."""
    return [member.value for member in enum_type]


# -- Models ----------------------------------------------------------------- #


class Image(Base):
    """Container images tracked by Sentinel.

    An image is a unique registry/repo/tag combination.
    """

    __tablename__ = "images"
    __table_args__ = (
        Index("idx_images_registry", "registry"),
        Index("idx_images_name", "repo_name"),
        Index("idx_images_tag", "tag"),
        UniqueConstraint("registry", "repo_name", "tag", name="uq_image_registry_repo_tag"),
        CheckConstraint(
            "char_length(repo_name) <= 512",
            name="chk_images_repo_length",
        ),
        CheckConstraint(
            "char_length(tag) <= 256",
            name="chk_images_tag_length",
        ),
    )

    id: Mapped[int] = mapped_column(PrimaryKey, primary_key=True, autoincrement=True)

    # Image coordinates
    registry_name: Mapped[ImageRegistry] = mapped_column(
        "registry",
        Enum(ImageRegistry, values_callable=_enum_values),
        nullable=False,
        default=ImageRegistry.DOCKER_HUB,
    )
    repo_name: Mapped[str] = mapped_column(String(512), nullable=False)
    tag: Mapped[str] = mapped_column(String(256), nullable=False, default="latest")
    digest: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Tracking
    discovered_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    last_scan_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)

    # Labels (user-assigned)
    labels: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    # Relationships
    scans = relationship("Scan", back_populates="image", lazy="selectin")
    findings = relationship("ScanFinding", back_populates="image", lazy="selectin")
    source = relationship("ImageSource", back_populates="image", uselist=False, lazy="selectin")

    @property
    def full_name(self) -> str:
        """Display reference. `repo_name` already includes any registry host."""
        return f"{self.repo_name}:{self.tag}"


class ImageSource(Base):
    """Where an image is built from, so a remediation can patch and rebuild it.

    `repository` is an HTTPS git URL, or a path relative to the worker's sources
    root (REMEDIATION_SOURCES_ROOT). `dockerfile_path` and `build_context` are
    relative to the repository root.
    """

    __tablename__ = "image_sources"

    id: Mapped[int] = mapped_column(PrimaryKey, primary_key=True, autoincrement=True)
    image_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("images.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    repository: Mapped[str] = mapped_column(String(1024), nullable=False)
    ref: Mapped[str] = mapped_column(String(256), nullable=False, default="HEAD")
    dockerfile_path: Mapped[str] = mapped_column(String(512), nullable=False, default="Dockerfile")
    build_context: Mapped[str] = mapped_column(String(512), nullable=False, default=".")
    build_args: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    test_command: Mapped[list | None] = mapped_column(JSON, nullable=True)
    updated_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now())

    image = relationship("Image", back_populates="source", lazy="joined")


class Scan(Base):
    """A single scan execution for one image.

    `target` is the exact reference handed to the scanners (an image reference,
    or `fs:<path>` for an internal filesystem scan). What the scan observed is
    recorded in `finding_observations`.
    """

    __tablename__ = "scans"
    __table_args__ = (
        Index("idx_scans_image_id", "image_id"),
        Index("idx_scans_status", "status"),
        Index("idx_scans_started_at", "started_at"),
        Index("idx_scans_image_status", "image_id", "status"),
        CheckConstraint(
            "char_length(scan_id) <= 64",
            name="chk_scans_id_length",
        ),
    )

    id: Mapped[int] = mapped_column(PrimaryKey, primary_key=True, autoincrement=True)

    # Unique ID for this scan execution (UUID or timestamp-based)
    scan_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)

    image_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("images.id", ondelete="CASCADE"), nullable=False)
    image = relationship("Image", back_populates="scans", lazy="joined")
    target: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    # Timing
    started_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    image_digest: Mapped[str | None] = mapped_column(String(128), nullable=True)
    scanner_versions: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    vulnerability_db_versions: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    # Status
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, values_callable=_enum_values), nullable=False, default=ScanStatus.PENDING
    )
    phase: Mapped[str] = mapped_column(String(64), nullable=False, default="queued")
    task_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Counters — set on completion
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)

    # Error
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    archived: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Metadata
    scheduler_type: Mapped[str | None] = mapped_column(String(32), nullable=True)  # 'manual', 'scheduled', 'ci'


class ScanFinding(Base):
    """One vulnerability on one image, tracked across scans.

    `fingerprint` = hash(CVE + package + version) identifies the finding.
    `vuln_key` = hash(CVE + package) ignores the version, so verification can
    ask whether a CVE is still present in a package after an upgrade. Each scan
    that sees the finding adds a `FindingObservation`; a later complete scan
    that does not see it sets `resolved_at`.
    """

    __tablename__ = "scan_findings"
    __table_args__ = (
        Index("idx_findings_image_id", "image_id"),
        Index("idx_findings_severity", "severity"),
        Index("idx_findings_fingerprint", "fingerprint"),
        Index("idx_findings_first_seen", "first_seen"),
        Index("idx_findings_vuln_key", "image_id", "vuln_key"),
        Index("idx_findings_resolved_at", "resolved_at"),
        Index("idx_findings_cve_image", "cve_id", "image_id"),
        UniqueConstraint("fingerprint", "image_id", name="uq_fingerprint_image"),
        CheckConstraint(
            "char_length(fingerprint) <= 128",
            name="chk_findings_fingerprint_length",
        ),
    )

    id: Mapped[int] = mapped_column(PrimaryKey, primary_key=True, autoincrement=True)

    # Links
    image_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("images.id", ondelete="CASCADE"), nullable=False)
    image = relationship("Image", back_populates="findings", lazy="joined")

    fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    vuln_key: Mapped[str] = mapped_column(String(64), nullable=False)

    # Package coordinates
    package_name: Mapped[str] = mapped_column(String(256))
    package_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    package_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Repository source coordinate, when the scanner inspected a checkout.
    # Container image package findings intentionally leave this null.
    file_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    # Vulnerability data
    cve_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    title: Mapped[str] = mapped_column(String(1024), default="")
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[Severity | None] = mapped_column(Enum(Severity, values_callable=_enum_values), nullable=True)

    # Source
    source: Mapped[FindingSource] = mapped_column(Enum(FindingSource, values_callable=_enum_values))
    scanner_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    vulnerability_db_version: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Fix information
    fixed_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    fix_available: Mapped[bool] = mapped_column(Boolean, default=False)

    # Tracking
    first_seen: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    reopened_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    assigned_to: Mapped[str | None] = mapped_column(String(128), nullable=True)
    remediation_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("remediations.id", ondelete="SET NULL"), nullable=True
    )

    # Relationships
    remediation = relationship("Remediation", back_populates="findings", lazy="selectin")


class FindingObservation(Base):
    """What one scan saw of one finding, so each scan's results stay intact."""

    __tablename__ = "finding_observations"
    __table_args__ = (
        UniqueConstraint("scan_id", "finding_id", name="uq_observation_scan_finding"),
        Index("idx_observations_finding_id", "finding_id"),
    )

    id: Mapped[int] = mapped_column(PrimaryKey, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String(64), ForeignKey("scans.scan_id", ondelete="CASCADE"), nullable=False)
    finding_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("scan_findings.id", ondelete="CASCADE"), nullable=False
    )
    severity: Mapped[Severity | None] = mapped_column(Enum(Severity, values_callable=_enum_values), nullable=True)
    fixed_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    file_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    finding = relationship("ScanFinding", lazy="joined")


class SeveritySnapshot(Base):
    """Daily snapshot of severity counts per image for trend charts.

    One row per image per day after the first scan of that day.
    """

    __tablename__ = "severity_snapshots"
    __table_args__ = (
        Index("idx_snapshots_image_date", "image_id", "snapshot_date", unique=True),
        Index("idx_snapshots_date", "snapshot_date"),
        UniqueConstraint("image_id", "snapshot_date", name="uq_image_date"),
    )

    id: Mapped[int] = mapped_column(PrimaryKey, primary_key=True, autoincrement=True)

    image_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("images.id", ondelete="CASCADE"), nullable=False)
    snapshot_date: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    total_open: Mapped[int] = mapped_column(Integer, default=0)
    newly_fixed: Mapped[int] = mapped_column(Integer, default=0)


# -- Security Policies ------------------------------------------------------ #


class Remediation(Base):
    """A remediation effort that may contain multiple actions."""

    __tablename__ = "remediations"
    __table_args__ = (
        Index("idx_remediations_status", "status"),
        Index("idx_remediations_image_id", "image_id"),
        Index("idx_remediations_created_at", "created_at"),
        Index("idx_remediations_approved_by", "approved_by"),
    )

    id: Mapped[int] = mapped_column(PrimaryKey, primary_key=True, autoincrement=True)

    image_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("images.id", ondelete="CASCADE"), nullable=False)
    image = relationship("Image", lazy="joined")

    status: Mapped[RemediationStatus] = mapped_column(
        Enum(RemediationStatus, values_callable=_enum_values), nullable=False, default=RemediationStatus.PENDING
    )

    # Trigger
    scan_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
    target_severities: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    # Result
    pr_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    pr_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    branch_name: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # Verification
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    approved_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Timing
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    findings = relationship("ScanFinding", back_populates="remediation", lazy="selectin")
    actions = relationship(
        "RemediationAction", back_populates="remediation", lazy="selectin", cascade="all, delete-orphan"
    )
    events = relationship(
        "RemediationEvent", back_populates="remediation", lazy="selectin", cascade="all, delete-orphan"
    )
    publications = relationship(
        "RemediationPublication", back_populates="remediation", lazy="selectin", cascade="all, delete-orphan"
    )


class RemediationPublication(Base):
    """Durable provider publication attempt and idempotency record."""

    __tablename__ = "remediation_publications"
    __table_args__ = (
        UniqueConstraint("provider", "repository", "idempotency_key", name="uq_remediation_publication_key"),
        Index("idx_remediation_publications_remediation_id", "remediation_id"),
        Index("idx_remediation_publications_status", "status"),
    )

    id: Mapped[int] = mapped_column(PrimaryKey, primary_key=True, autoincrement=True)
    remediation_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("remediations.id", ondelete="CASCADE"), nullable=False
    )
    remediation = relationship("Remediation", back_populates="publications", lazy="joined")
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    repository: Mapped[str] = mapped_column(String(256), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(256), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    provider_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    merged_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    merge_commit: Mapped[str | None] = mapped_column(String(64), nullable=True)
    observed_digest: Mapped[str | None] = mapped_column(String(71), nullable=True)
    verification_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    verification_detail: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    scan_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    post_merge_scan_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    findings_before: Mapped[int | None] = mapped_column(Integer, nullable=True)
    findings_after: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rollback_command: Mapped[list] = mapped_column(JSON, nullable=False, default=list)


class RemediationWebhookEvent(Base):
    """Replay-protected provider callback receipt."""

    __tablename__ = "remediation_webhook_events"
    __table_args__ = (
        UniqueConstraint("provider", "event_id", name="uq_remediation_webhook_event"),
        Index("idx_remediation_webhook_events_remediation_id", "remediation_id"),
    )

    id: Mapped[int] = mapped_column(PrimaryKey, primary_key=True, autoincrement=True)
    remediation_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("remediations.id", ondelete="SET NULL"), nullable=True
    )
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    event_id: Mapped[str] = mapped_column(String(256), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class RemediationAction(Base):
    """Individual action taken within a remediation.

    E.g. bumping a base image tag, updating a lockfile, removing a package.
    """

    __tablename__ = "remediation_actions"
    __table_args__ = (
        Index("idx_remediation_actions_remediation_id", "remediation_id"),
        Index("idx_remediation_actions_type", "action_type"),
    )

    id: Mapped[int] = mapped_column(PrimaryKey, primary_key=True, autoincrement=True)

    remediation_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("remediations.id", ondelete="CASCADE"), nullable=False
    )
    remediation = relationship("Remediation", back_populates="actions", lazy="joined")

    action_type: Mapped[RemediationActionType] = mapped_column(
        Enum(RemediationActionType, values_callable=_enum_values), nullable=False
    )

    # Before / after values
    file_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    before_value: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    after_value: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    # Result
    success: Mapped[bool] = mapped_column(Boolean, default=False)
    detail: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class RemediationEvent(Base):
    """Durable lifecycle event emitted by a remediation worker."""

    __tablename__ = "remediation_events"
    __table_args__ = (
        Index("idx_remediation_events_remediation_id", "remediation_id"),
        Index("idx_remediation_events_sequence", "remediation_id", "sequence"),
    )

    id: Mapped[int] = mapped_column(PrimaryKey, primary_key=True, autoincrement=True)
    remediation_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("remediations.id", ondelete="CASCADE"), nullable=False
    )
    remediation = relationship("Remediation", back_populates="events", lazy="joined")
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    sequence: Mapped[int | None] = mapped_column(Integer, nullable=True)
    detail: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


# -- Compliance Reporting --------------------------------------------------- #


class AuditLog(Base):
    """Append-only audit log for security and system events."""

    __tablename__ = "audit_log"
    __table_args__ = (
        Index("idx_audit_event_type", "event_type"),
        Index("idx_audit_timestamp", "timestamp"),
        Index("idx_audit_image_id", "image_id"),
        Index("idx_audit_entity_id", "entity_type", "entity_id"),
    )

    id: Mapped[int] = mapped_column(PrimaryKey, primary_key=True, autoincrement=True)

    timestamp: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False)
    event_type: Mapped[AuditEventType] = mapped_column(
        Enum(AuditEventType, values_callable=_enum_values), nullable=False
    )
    entity_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    entity_id: Mapped[str | None] = mapped_column(String(128), nullable=True)

    image_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("images.id", ondelete="SET NULL"), nullable=True
    )

    detail: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    previous_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    record_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    actor: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # 'agent', 'scheduler', 'user', 'system'
    actor_kind: Mapped[str | None] = mapped_column(String(16), nullable=True)
