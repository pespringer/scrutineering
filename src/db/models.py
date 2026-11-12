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
    Column,
    DateTime,
    Dialect,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    Interval,
    JSON,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    CheckConstraint,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.sql import func


# -- Base ------------------------------------------------------------------- #

class Base(DeclarativeBase):
    """Declarative base — all models inherit from this."""
    pass


# -- Enums ------------------------------------------------------------------ #

class Severity(str, enum.Enum):
    """Standardised severity levels."""
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    UNKNOWN  = "unknown"


class FindingSource(str, enum.Enum):
    """Scanner that produced the finding."""
    TRIVY = "trivy"
    GRYPE = "grype"


class ImageRegistry(str, enum.Enum):
    """Known container registries."""
    DOCKER_HUB   = "dockerhub"
    GCR          = "gcr"
    ECR          = "ecr"
    GHCR         = "ghcr"
    GITLAB       = "gitlab"
    HARBOR       = "harbor"
    QUAY         = "quay"
    OTHER        = "other"


class RemediationStatus(str, enum.Enum):
    """Lifecycle states of a remediation effort."""
    PENDING         = "pending"
    ANALYZING       = "analyzing"
    PATCHING        = "patching"
    BUILDING        = "building"
    VERIFYING       = "verifying"
    PR_OPENED       = "pr_opened"
    COMPLETED       = "completed"
    FAILED          = "failed"
    SKIPPED         = "skipped"
    REQUIRES_REVIEW = "requires_review"


class RemediationActionType(str, enum.Enum):
    """Types of remediation actions."""
    BASE_IMAGE_BUMP    = "base_image_bump"
    DEPENDENCY_UPDATE  = "dependency_update"
    CONFIG_CHANGE      = "config_change"
    PACKAGE_REMOVAL    = "package_removal"
    CUSTOM             = "custom"


class PolicyType(str, enum.Enum):
    """Kinds of security policy."""
    SEVERITY_THRESHOLD   = "severity_threshold"
    IMAGE_ALLOWLIST      = "image_allowlist"
    IMAGE_DENYLIST       = "image_denylist"
    AUTO_REMEDIATE       = "auto_remediate"
    NOTIFICATION         = "notification"
    COMPLIANCE           = "compliance"
    RETENTION            = "retention"


class PolicyAction(str, enum.Enum):
    """Action taken when a policy matches."""
    BLOCK        = "block"
    ALERT        = "alert"
    AUTO_FIX     = "auto_fix"
    SKIP         = "skip"
    REQUIRE_APPROVAL = "require_approval"
    ESCALATE     = "escalate"


class AuditEventType(str, enum.Enum):
    """Types of audit events."""
    SCAN_STARTED   = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED    = "scan_failed"
    SCAN_CANCELLED = "scan_cancelled"
    FINDING_CREATED = "finding_created"
    FINDING_CLOSED = "finding_closed"
    REMEDIATION_STARTED  = "remediation_started"
    REMEDIATION_COMPLETED = "remediation_completed"
    REMEDIATION_FAILED    = "remediation_failed"
    POLICY_CREATED = "policy_created"
    POLICY_UPDATED = "policy_updated"
    POLICY_VIOLATED = "policy_violated"
    COMPLIANCE_REPORT_GENERATED = "compliance_report_generated"
    CONFIG_CHANGED   = "config_changed"
    USER_LOGIN       = "user_login"
    SYSTEM_ERROR     = "system_error"


class ScanStatus(str, enum.Enum):
    """Status of an individual image scan."""
    PENDING    = "pending"
    RUNNING    = "running"
    COMPLETED  = "completed"
    FAILED     = "failed"
    CANCELLED  = "cancelled"


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
        UniqueConstraint("registry", "repo_name", "tag",
                         name="uq_image_registry_repo_tag"),
        CheckConstraint(
            "char_length(registry) <= 32",
            name="chk_images_registry_length",
        ),
        CheckConstraint(
            "char_length(repo_name) <= 512",
            name="chk_images_repo_length",
        ),
        CheckConstraint(
            "char_length(tag) <= 256",
            name="chk_images_tag_length",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True,
                                     autoincrement=True)

    # Image coordinates
    registry_name: Mapped[ImageRegistry] = mapped_column(
        "registry", Enum(ImageRegistry, values_callable=_enum_values), nullable=False,
        default=ImageRegistry.DOCKER_HUB,
    )
    repo_name: Mapped[str] = mapped_column(String(512), nullable=False)
    tag: Mapped[str] = mapped_column(String(256), nullable=False,
                                      default="latest")
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
    findings = relationship("ScanFinding", back_populates="image",
                            lazy="selectin")

    @property
    def full_name(self) -> str:
        """Return the canonical image reference, preferring its digest."""
        prefix = self.registry_name.value if self.registry_name != ImageRegistry.DOCKER_HUB else ""
        if self.digest:
            return f"{prefix + '/' if prefix else ''}{self.repo_name}@{self.digest}"
        if prefix:
            return f"{prefix}/{self.repo_name}:{self.tag}"
        return f"{self.repo_name}:{self.tag}"


class Scan(Base):
    """A single scan execution for one image.

    Each scan may run both Trivy and Grype; their raw outputs are
    stored in `raw_scan_results`.
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

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True,
                                     autoincrement=True)

    # Unique ID for this scan execution (UUID or timestamp-based)
    scan_id: Mapped[str] = mapped_column(String(64), nullable=False,
                                          unique=True)

    image_id: Mapped[int] = mapped_column(BigInteger,
                                           ForeignKey("images.id",
                                                       ondelete="CASCADE"),
                                           nullable=False)
    image = relationship("Image", back_populates="scans", lazy="joined")

    # Timing
    started_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime,
                                                           nullable=True)
    duration_seconds: Mapped[float | None] = mapped_column(
        Float, nullable=True)
    image_digest: Mapped[str | None] = mapped_column(String(128), nullable=True)
    scanner_versions: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    vulnerability_db_versions: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    # Status
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, values_callable=_enum_values), nullable=False, default=ScanStatus.PENDING)

    # Counters — set on completion
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)

    # Error
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Metadata
    scheduler_type: Mapped[str | None] = mapped_column(
        String(32), nullable=True)  # 'manual', 'scheduled', 'ci'


class ScanFinding(Base):
    """A single deduplicated vulnerability finding on an image.

    Fingerprint is deterministic: hash(CVE + package_name + package_version)
    so the same finding can be tracked across scans.
    """
    __tablename__ = "scan_findings"
    __table_args__ = (
        Index("idx_findings_image_id", "image_id"),
        Index("idx_findings_severity", "severity"),
        Index("idx_findings_fingerprint", "fingerprint"),
        Index("idx_findings_first_seen", "first_seen"),
        Index("idx_findings_remediated", "remediated"),
        Index("idx_findings_cve_image", "cve_id", "image_id"),
        UniqueConstraint("fingerprint", "image_id",
                         name="uq_fingerprint_image"),
        CheckConstraint(
            "char_length(fingerprint) <= 128",
            name="chk_findings_fingerprint_length",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True,
                                     autoincrement=True)

    # Links
    scan_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    image_id: Mapped[int] = mapped_column(BigInteger,
                                           ForeignKey("images.id",
                                                       ondelete="CASCADE"),
                                           nullable=False)
    image = relationship("Image", back_populates="findings", lazy="joined")

    fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)

    # Package coordinates
    package_name: Mapped[str] = mapped_column(String(256))
    package_version: Mapped[str | None] = mapped_column(String(64),
                                                         nullable=True)
    package_type: Mapped[str | None] = mapped_column(String(64),
                                                      nullable=True)

    # Vulnerability data
    cve_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    title: Mapped[str] = mapped_column(String(1024), default="")
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[Severity | None] = mapped_column(
        Enum(Severity, values_callable=_enum_values), nullable=True)

    # Source
    source: Mapped[FindingSource] = mapped_column(Enum(FindingSource, values_callable=_enum_values))
    scanner_version: Mapped[str | None] = mapped_column(String(64),
                                                         nullable=True)
    vulnerability_db_version: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Fix information
    fixed_version: Mapped[str | None] = mapped_column(String(64),
                                                       nullable=True)
    fix_available: Mapped[bool] = mapped_column(Boolean, default=False)

    # Tracking
    first_seen: Mapped[datetime] = mapped_column(DateTime,
                                                  server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime,
                                                 server_default=func.now())
    remediated: Mapped[bool] = mapped_column(Boolean, default=False)
    remediation_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("remediations.id", ondelete="SET NULL"),
        nullable=True)

    # Relationships
    remediation = relationship("Remediation", back_populates="findings",
                               lazy="selectin")


class RawScanResult(Base):
    """Raw scan output stored for audit/forensics.

    One row per scanner per scan execution. JSONB keeps the full
    scanner output without losing fidelity.
    """
    __tablename__ = "raw_scan_results"
    __table_args__ = (
        Index("idx_raw_results_image_id", "image_id"),
        Index("idx_raw_results_scanner", "scanner_source"),
        Index("idx_raw_results_scan_id", "scan_id"),
        Index("idx_raw_results_created_at", "created_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True,
                                     autoincrement=True)

    image_id: Mapped[int] = mapped_column(BigInteger,
                                           ForeignKey("images.id",
                                                       ondelete="CASCADE"),
                                           nullable=False)
    scan_id: Mapped[str] = mapped_column(String(64), nullable=False)
    scanner_source: Mapped[FindingSource] = mapped_column(
        Enum(FindingSource, values_callable=_enum_values), nullable=False)
    scanner_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    vulnerability_db_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    raw_output: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime,
                                                  server_default=func.now())
    file_size_bytes: Mapped[int | None] = mapped_column(BigInteger,
                                                         nullable=True)


class SeveritySnapshot(Base):
    """Daily snapshot of severity counts per image for trend charts.

    One row per image per day after the first scan of that day.
    """
    __tablename__ = "severity_snapshots"
    __table_args__ = (
        Index("idx_snapshots_image_date", "image_id", "snapshot_date",
              unique=True),
        Index("idx_snapshots_date", "snapshot_date"),
        UniqueConstraint("image_id", "snapshot_date",
                         name="uq_image_date"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True,
                                     autoincrement=True)

    image_id: Mapped[int] = mapped_column(BigInteger,
                                           ForeignKey("images.id",
                                                       ondelete="CASCADE"),
                                           nullable=False)
    snapshot_date: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    total_open: Mapped[int] = mapped_column(Integer, default=0)
    newly_fixed: Mapped[int] = mapped_column(Integer, default=0)


# -- Security Policies ------------------------------------------------------ #

class SecurityPolicy(Base):
    """User-defined security policy controlling Sentinel behaviour."""
    __tablename__ = "security_policies"
    __table_args__ = (
        Index("idx_policies_type", "policy_type"),
        Index("idx_policies_enabled", "enabled"),
        Index("idx_policies_priority", "priority"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True,
                                     autoincrement=True)

    name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    policy_type: Mapped[PolicyType] = mapped_column(Enum(PolicyType, values_callable=_enum_values),
                                                     nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    priority: Mapped[int] = mapped_column(Integer, default=0)

    # Rule definition stored as JSON
    # Examples:
    #   auto_remediate: {"severities": ["critical", "high"], "targets": ["npm", "pip"]}
    #   severity_threshold: {"max_critical": 0, "max_high": 5, "action": "block"}
    rules: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    action: Mapped[PolicyAction] = mapped_column(Enum(PolicyAction, values_callable=_enum_values),
                                                  nullable=False,
                                                  default=PolicyAction.ALERT)

    # Image scope (empty list = all images)
    image_filters: Mapped[dict] = mapped_column(
        JSON, nullable=False, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime,
                                                  server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now())
    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True)

    evaluations = relationship("PolicyEvaluation", back_populates="policy",
                               lazy="selectin")


class PolicyEvaluation(Base):
    """Log of policy evaluations — what matched and what action was taken."""
    __tablename__ = "policy_evaluations"
    __table_args__ = (
        Index("idx_evaluations_policy_id", "policy_id"),
        Index("idx_evaluations_scan_id", "scan_id"),
        Index("idx_evaluations_violated", "violated"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True,
                                     autoincrement=True)

    policy_id: Mapped[int] = mapped_column(BigInteger,
                                            ForeignKey("security_policies.id",
                                                        ondelete="CASCADE"),
                                            nullable=False)
    policy = relationship("SecurityPolicy", back_populates="evaluations",
                          lazy="joined")

    scan_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    finding_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("scan_findings.id", ondelete="SET NULL"),
        nullable=True)

    evaluated_at: Mapped[datetime] = mapped_column(DateTime,
                                                    server_default=func.now())
    violated: Mapped[bool] = mapped_column(Boolean, default=False)
    detail: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    action_taken: Mapped[PolicyAction | None] = mapped_column(
        Enum(PolicyAction, values_callable=_enum_values), nullable=True)


# -- Remediations ----------------------------------------------------------- #

class Remediation(Base):
    """A remediation effort that may contain multiple actions."""
    __tablename__ = "remediations"
    __table_args__ = (
        Index("idx_remediations_status", "status"),
        Index("idx_remediations_image_id", "image_id"),
        Index("idx_remediations_created_at", "created_at"),
        Index("idx_remediations_approved_by", "approved_by"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True,
                                     autoincrement=True)

    image_id: Mapped[int] = mapped_column(BigInteger,
                                           ForeignKey("images.id",
                                                       ondelete="CASCADE"),
                                           nullable=False)
    image = relationship("Image", lazy="joined")

    status: Mapped[RemediationStatus] = mapped_column(
        Enum(RemediationStatus, values_callable=_enum_values), nullable=False,
        default=RemediationStatus.PENDING)

    # Trigger
    scan_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
    target_severities: Mapped[dict] = mapped_column(
        JSON, nullable=False, default=dict)

    # Result
    pr_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    pr_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    branch_name: Mapped[str | None] = mapped_column(String(512),
                                                     nullable=True)

    # Verification
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    approval_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    approved_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    verification_findings_before: Mapped[int] = mapped_column(
        Integer, default=0)
    verification_findings_after: Mapped[int] = mapped_column(
        Integer, default=0)

    # Timing
    created_at: Mapped[datetime] = mapped_column(DateTime,
                                                  server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime,
                                                         nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime,
                                                           nullable=True)

    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    findings = relationship("ScanFinding", back_populates="remediation",
                            lazy="selectin")
    actions = relationship("RemediationAction", back_populates="remediation",
                           lazy="selectin",
                           cascade="all, delete-orphan")
    events = relationship("RemediationEvent", back_populates="remediation",
                          lazy="selectin", cascade="all, delete-orphan")
    publications = relationship("RemediationPublication", back_populates="remediation", lazy="selectin", cascade="all, delete-orphan")


class RemediationPublication(Base):
    """Durable provider publication attempt and idempotency record."""
    __tablename__ = "remediation_publications"
    __table_args__ = (
        UniqueConstraint("provider", "repository", "idempotency_key", name="uq_remediation_publication_key"),
        Index("idx_remediation_publications_remediation_id", "remediation_id"),
        Index("idx_remediation_publications_status", "status"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    remediation_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("remediations.id", ondelete="CASCADE"), nullable=False)
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
    findings_before: Mapped[int | None] = mapped_column(Integer, nullable=True)
    findings_after: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rollback_command: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    recovery_requests = relationship("RemediationRecoveryRequest", back_populates="publication", lazy="selectin", cascade="all, delete-orphan")
    release_evidence = relationship("RemediationReleaseEvidence", back_populates="publication", lazy="selectin", cascade="all, delete-orphan")
    alert_evidence = relationship("RemediationAlertEvidence", back_populates="publication", lazy="selectin", cascade="all, delete-orphan")


class RemediationReleaseEvidence(Base):
    """Durable deployment evidence attached to a provider publication."""
    __tablename__ = "remediation_release_evidence"
    __table_args__ = (
        UniqueConstraint("publication_id", "evidence_key", name="uq_remediation_release_evidence_key"),
        Index("idx_remediation_release_evidence_publication_id", "publication_id"),
        Index("idx_remediation_release_evidence_status", "status"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    publication_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("remediation_publications.id", ondelete="CASCADE"), nullable=False)
    publication = relationship("RemediationPublication", back_populates="release_evidence", lazy="joined")
    evidence_key: Mapped[str] = mapped_column(String(128), nullable=False)
    expected_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    observed_digest: Mapped[str | None] = mapped_column(String(71), nullable=True)
    scan_status: Mapped[str] = mapped_column(String(32), nullable=False)
    findings_before: Mapped[int] = mapped_column(Integer, nullable=False)
    findings_after: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    verification_detail: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    verified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class RemediationRecoveryRequest(Base):
    """Durable, idempotent operator request for a stale publication."""
    __tablename__ = "remediation_recovery_requests"
    __table_args__ = (
        UniqueConstraint("publication_id", "idempotency_key", name="uq_remediation_recovery_request_key"),
        Index("idx_remediation_recovery_requests_publication_id", "publication_id"),
        Index("idx_remediation_recovery_requests_status", "status"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    publication_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("remediation_publications.id", ondelete="CASCADE"), nullable=False)
    publication = relationship("RemediationPublication", back_populates="recovery_requests", lazy="joined")
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(256), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="requested")
    note: Mapped[str] = mapped_column(Text, nullable=False, default="")
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    lease_owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    requested_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class RemediationAlertEvidence(Base):
    """Durable receipt for an external alert delivery attempt."""
    __tablename__ = "remediation_alert_evidence"
    __table_args__ = (
        UniqueConstraint("publication_id", "delivery_key", name="uq_remediation_alert_evidence_key"),
        Index("idx_remediation_alert_evidence_publication_id", "publication_id"),
        Index("idx_remediation_alert_evidence_status", "status"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    publication_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("remediation_publications.id", ondelete="CASCADE"), nullable=False)
    publication = relationship("RemediationPublication", back_populates="alert_evidence", lazy="joined")
    delivery_key: Mapped[str] = mapped_column(String(128), nullable=False)
    receiver: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    response_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    detail: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class RemediationAlertDelivery(Base):
    """Queue state for receiver-independent alert delivery attempts."""
    __tablename__ = "remediation_alert_deliveries"
    __table_args__ = (
        UniqueConstraint("publication_id", "delivery_key", name="uq_remediation_alert_delivery_key"),
        Index("idx_remediation_alert_deliveries_status", "status"),
        Index("idx_remediation_alert_deliveries_next_attempt_at", "next_attempt_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    publication_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("remediation_publications.id", ondelete="CASCADE"), nullable=False)
    publication = relationship("RemediationPublication", lazy="joined")
    delivery_key: Mapped[str] = mapped_column(String(128), nullable=False)
    receiver: Mapped[str] = mapped_column(String(128), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class RemediationReconciliationRun(Base):
    """Durable health record for scheduled publication reconciliation."""
    __tablename__ = "remediation_reconciliation_runs"
    __table_args__ = (Index("idx_remediation_reconciliation_runs_started_at", "started_at"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    discovered: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    events_recorded: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class RemediationWebhookEvent(Base):
    """Replay-protected provider callback receipt."""
    __tablename__ = "remediation_webhook_events"
    __table_args__ = (
        UniqueConstraint("provider", "event_id", name="uq_remediation_webhook_event"),
        Index("idx_remediation_webhook_events_remediation_id", "remediation_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    remediation_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("remediations.id", ondelete="SET NULL"), nullable=True)
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

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True,
                                     autoincrement=True)

    remediation_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("remediations.id", ondelete="CASCADE"),
        nullable=False)
    remediation = relationship("Remediation", back_populates="actions",
                               lazy="joined")

    action_type: Mapped[RemediationActionType] = mapped_column(
        Enum(RemediationActionType, values_callable=_enum_values), nullable=False)

    # Before / after values
    file_path: Mapped[str | None] = mapped_column(String(1024),
                                                   nullable=True)
    before_value: Mapped[str | None] = mapped_column(String(1024),
                                                      nullable=True)
    after_value: Mapped[str | None] = mapped_column(String(1024),
                                                     nullable=True)

    # Result
    success: Mapped[bool] = mapped_column(Boolean, default=False)
    detail: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime,
                                                  server_default=func.now())


class RemediationEvent(Base):
    """Durable lifecycle event emitted by a remediation worker."""
    __tablename__ = "remediation_events"
    __table_args__ = (Index("idx_remediation_events_remediation_id", "remediation_id"), Index("idx_remediation_events_sequence", "remediation_id", "sequence"))

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    remediation_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("remediations.id", ondelete="CASCADE"), nullable=False)
    remediation = relationship("Remediation", back_populates="events", lazy="joined")
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    sequence: Mapped[int | None] = mapped_column(Integer, nullable=True)
    detail: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


# -- Compliance Reporting --------------------------------------------------- #

class ComplianceReport(Base):
    """Metadata for a generated compliance report."""
    __tablename__ = "compliance_reports"
    __table_args__ = (
        Index("idx_compliance_reports_format", "report_format"),
        Index("idx_compliance_reports_generated_at", "generated_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True,
                                     autoincrement=True)

    title: Mapped[str] = mapped_column(String(512), nullable=False)
    report_format: Mapped[str] = mapped_column(String(16), nullable=False)
    scope: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    generated_at: Mapped[datetime] = mapped_column(DateTime,
                                                    server_default=func.now())
    file_path: Mapped[str | None] = mapped_column(String(2048),
                                                   nullable=True)
    summary: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    generated_by: Mapped[str | None] = mapped_column(String(64),
                                                      nullable=True)


# -- Audit Log -------------------------------------------------------------- #

class AuditLog(Base):
    """Append-only audit log for security and system events."""
    __tablename__ = "audit_log"
    __table_args__ = (
        Index("idx_audit_event_type", "event_type"),
        Index("idx_audit_timestamp", "timestamp"),
        Index("idx_audit_image_id", "image_id"),
        Index("idx_audit_entity_id", "entity_type", "entity_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True,
                                     autoincrement=True)

    timestamp: Mapped[datetime] = mapped_column(DateTime,
                                                 server_default=func.now(),
                                                 nullable=False)
    event_type: Mapped[AuditEventType] = mapped_column(Enum(AuditEventType, values_callable=_enum_values),
                                                        nullable=False)
    entity_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    entity_id: Mapped[str | None] = mapped_column(String(128), nullable=True)

    image_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("images.id", ondelete="SET NULL"),
        nullable=True)

    detail: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    previous_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    record_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    actor: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # 'agent', 'scheduler', 'user', 'system'
    actor_kind: Mapped[str | None] = mapped_column(String(16), nullable=True)


class AuditChainAnchor(Base):
    """Durable receipt for an externally anchored audit-chain head."""
    __tablename__ = "audit_chain_anchors"
    __table_args__ = (
        Index("idx_audit_chain_anchors_head_hash", "head_hash"),
        UniqueConstraint("anchor_id", name="uq_audit_chain_anchors_anchor_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    anchor_id: Mapped[str] = mapped_column(String(256), nullable=False)
    head_hash: Mapped[str] = mapped_column(String(71), nullable=False)
    record_id: Mapped[str] = mapped_column(String(128), nullable=False)
    anchored_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False)


# -- Forensics -------------------------------------------------------------- #

class ForensicSnapshot(Base):
    """Point-in-time forensic snapshot of a container."""
    __tablename__ = "forensic_snapshots"
    __table_args__ = (
        Index("idx_forensic_snapshots_container", "container_id"),
        Index("idx_forensic_snapshots_captured_at", "captured_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True,
                                     autoincrement=True)
    snapshot_id: Mapped[str] = mapped_column(String(128), nullable=False,
                                              unique=True)
    container_id: Mapped[str] = mapped_column(String(128), nullable=False)
    captured_at: Mapped[datetime] = mapped_column(DateTime,
                                                 server_default=func.now())
    image_name: Mapped[str | None] = mapped_column(String(512),
                                                    nullable=True)
    snapshot_hash: Mapped[str | None] = mapped_column(String(64),
                                                       nullable=True)
    # Full snapshot data as JSON
    snapshot_data: Mapped[dict] = mapped_column(JSON, nullable=False,
                                                 default=dict)
    artifact_path: Mapped[str | None] = mapped_column(String(2048),
                                                       nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(64),
                                                    nullable=True)


class ForensicNetworkFlow(Base):
    """Network flow record for forensic analysis."""
    __tablename__ = "forensic_network_flows"
    __table_args__ = (
        Index("idx_forensic_flows_container", "container_id"),
        Index("idx_forensic_flows_timestamp", "timestamp"),
        Index("idx_forensic_flows_external", "is_external"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True,
                                     autoincrement=True)
    container_id: Mapped[str] = mapped_column(String(128), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime,
                                                 server_default=func.now())
    protocol: Mapped[str] = mapped_column(String(16), nullable=False)
    src_addr: Mapped[str] = mapped_column(String(64), nullable=False)
    src_port: Mapped[int] = mapped_column(Integer, nullable=False)
    dst_addr: Mapped[str] = mapped_column(String(64), nullable=False)
    dst_port: Mapped[int] = mapped_column(Integer, nullable=False)
    bytes_sent: Mapped[int] = mapped_column(BigInteger, default=0)
    bytes_recv: Mapped[int] = mapped_column(BigInteger, default=0)
    is_external: Mapped[bool] = mapped_column(Boolean, default=False)
    state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    detail: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


# -- Container Runtime Monitoring ------------------------------------------- #

class ContainerRuntime(Base):
    """Runtime behaviour monitoring data for active containers."""
    __tablename__ = "container_runtime"
    __table_args__ = (
        Index("idx_runtime_container_id", "container_id"),
        Index("idx_runtime_image_id", "image_id"),
        Index("idx_runtime_timestamp", "timestamp"),
        Index("idx_runtime_event_type", "event_type"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True,
                                     autoincrement=True)

    container_id: Mapped[str] = mapped_column(String(128), nullable=False)
    image_id: Mapped[int] = mapped_column(BigInteger,
                                           ForeignKey("images.id",
                                                       ondelete="CASCADE"),
                                           nullable=False)
    image = relationship("Image", lazy="joined")

    timestamp: Mapped[datetime] = mapped_column(DateTime,
                                                 server_default=func.now(),
                                                 nullable=False)

    # Event classification
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    # e.g. 'network_connection', 'file_write', 'process_spawn',
    #      'privilege_escalation', 'syscall'
    severity: Mapped[Severity | None] = mapped_column(Enum(Severity, values_callable=_enum_values),
                                                       nullable=True)

    # Details — highly variable per event type
    detail: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    source: Mapped[str | None] = mapped_column(String(128),
                                                nullable=True)  # e.g. docker events, falco
