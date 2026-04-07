"""
Revises:
Create Date: 2026-04-05 21:00:00.000000

Initial database schema for Container Sentinel.
Creates all tables: images, scans, scan_findings, raw_scan_results,
severity_snapshots, security_policies, policy_evaluations, remediations,
remediation_actions, compliance_reports, audit_log, container_runtime.
"""
from alembic import op
import sqlalchemy as sa

revision = "001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # -- Custom PostgreSQL ENUM types ----------------------------------------
    sa.Enum("dockerhub", "gcr", "ecr", "ghcr", "gitlab", "harbor", "quay", "other",
            name="image_registry").create(op.get_bind())

    sa.Enum("critical", "high", "medium", "low", "unknown",
            name="severity").create(op.get_bind())

    sa.Enum("pending", "running", "completed", "failed", "cancelled",
            name="scan_status").create(op.get_bind())

    sa.Enum("trivy", "grype",
            name="finding_source").create(op.get_bind())

    sa.Enum("pending", "analyzing", "patching", "building", "verifying",
            "pr_opened", "completed", "failed", "skipped", "requires_review",
            name="remediation_status").create(op.get_bind())

    sa.Enum("base_image_bump", "dependency_update", "config_change",
            "package_removal", "custom",
            name="remediation_action_type").create(op.get_bind())

    sa.Enum("severity_threshold", "image_allowlist", "image_denylist",
            "auto_remediate", "notification", "compliance", "retention",
            name="policy_type").create(op.get_bind())

    sa.Enum("block", "alert", "auto_fix", "skip", "require_approval", "escalate",
            name="policy_action").create(op.get_bind())

    sa.Enum("scan_started", "scan_completed", "scan_failed",
            "finding_created", "finding_closed",
            "remediation_started", "remediation_completed", "remediation_failed",
            "policy_created", "policy_updated", "policy_violated",
            "compliance_report_generated",
            "config_changed", "user_login", "system_error",
            name="audit_event_type").create(op.get_bind())

    # -- images --------------------------------------------------------------
    op.create_table(
        "images",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("registry", sa.Enum("dockerhub", "gcr", "ecr", "ghcr", "gitlab",
                                       "harbor", "quay", "other",
                                       name="image_registry"),
                  nullable=False, server_default="dockerhub"),
        sa.Column("repo_name", sa.String(512), nullable=False),
        sa.Column("tag", sa.String(256), nullable=False, server_default="latest"),
        sa.Column("digest", sa.String(128), nullable=True),
        sa.Column("discovered_at", sa.DateTime, server_default=sa.text("now()"), nullable=False),
        sa.Column("last_scan_id", sa.String(64), nullable=True),
        sa.Column("last_scan_at", sa.DateTime, nullable=True),
        sa.Column("active", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("labels", sa.JSON, nullable=False, server_default="{}"),
        sa.UniqueConstraint("registry", "repo_name", "tag", name="uq_image_registry_repo_tag"),
        sa.CheckConstraint("char_length(registry) <= 32", name="chk_images_registry_length"),
        sa.CheckConstraint("char_length(repo_name) <= 512", name="chk_images_repo_length"),
        sa.CheckConstraint("char_length(tag) <= 256", name="chk_images_tag_length"),
        sa.Index("idx_images_registry", "registry"),
        sa.Index("idx_images_name", "repo_name"),
        sa.Index("idx_images_tag", "tag"),
    )

    # -- scans ---------------------------------------------------------------
    op.create_table(
        "scans",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("scan_id", sa.String(64), nullable=False, unique=True),
        sa.Column("image_id", sa.BigInteger, sa.ForeignKey("images.id", ondelete="CASCADE"), nullable=False),
        sa.Column("started_at", sa.DateTime, server_default=sa.text("now()"), nullable=False),
        sa.Column("completed_at", sa.DateTime, nullable=True),
        sa.Column("duration_seconds", sa.Float, nullable=True),
        sa.Column("status", sa.Enum("pending", "running", "completed", "failed", "cancelled",
                                     name="scan_status"),
                  nullable=False, server_default="pending"),
        sa.Column("total_findings", sa.Integer, nullable=False, server_default="0"),
        sa.Column("critical_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("high_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("medium_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("low_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("scheduler_type", sa.String(32), nullable=True),
        sa.CheckConstraint("char_length(scan_id) <= 64", name="chk_scans_id_length"),
        sa.Index("idx_scans_image_id", "image_id"),
        sa.Index("idx_scans_status", "status"),
        sa.Index("idx_scans_started_at", "started_at"),
        sa.Index("idx_scans_image_status", "image_id", "status"),
    )

    # -- scan_findings -------------------------------------------------------
    op.create_table(
        "scan_findings",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("scan_id", sa.String(64), nullable=True),
        sa.Column("image_id", sa.BigInteger, sa.ForeignKey("images.id", ondelete="CASCADE"), nullable=False),
        sa.Column("fingerprint", sa.String(128), nullable=False),
        sa.Column("package_name", sa.String(256), nullable=False),
        sa.Column("package_version", sa.String(64), nullable=True),
        sa.Column("package_type", sa.String(64), nullable=True),
        sa.Column("cve_id", sa.String(32), nullable=True),
        sa.Column("title", sa.String(1024), nullable=False, server_default=""),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("severity", sa.Enum("critical", "high", "medium", "low", "unknown",
                                       name="severity"), nullable=True),
        sa.Column("source", sa.Enum("trivy", "grype", name="finding_source"), nullable=False),
        sa.Column("scanner_version", sa.String(64), nullable=True),
        sa.Column("fixed_version", sa.String(64), nullable=True),
        sa.Column("fix_available", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("first_seen", sa.DateTime, server_default=sa.text("now()"), nullable=False),
        sa.Column("last_seen", sa.DateTime, server_default=sa.text("now()"), nullable=False),
        sa.Column("remediated", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("remediation_id", sa.BigInteger, nullable=True),
        sa.UniqueConstraint("fingerprint", "image_id", name="uq_fingerprint_image"),
        sa.CheckConstraint("char_length(fingerprint) <= 128", name="chk_findings_fingerprint"),
        sa.Index("idx_findings_image_id", "image_id"),
        sa.Index("idx_findings_severity", "severity"),
        sa.Index("idx_findings_fingerprint", "fingerprint"),
        sa.Index("idx_findings_first_seen", "first_seen"),
        sa.Index("idx_findings_remediated", "remediated"),
        sa.Index("idx_findings_cve_image", "cve_id", "image_id"),
    )

    # -- raw_scan_results ----------------------------------------------------
    op.create_table(
        "raw_scan_results",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("image_id", sa.BigInteger, sa.ForeignKey("images.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_id", sa.String(64), nullable=False),
        sa.Column("scanner_source", sa.Enum("trivy", "grype", name="finding_source"), nullable=False),
        sa.Column("raw_output", sa.JSON, nullable=False),
        sa.Column("created_at", sa.DateTime, server_default=sa.text("now()"), nullable=False),
        sa.Column("file_size_bytes", sa.BigInteger, nullable=True),
        sa.Index("idx_raw_results_image_id", "image_id"),
        sa.Index("idx_raw_results_scanner", "scanner_source"),
        sa.Index("idx_raw_results_scan_id", "scan_id"),
        sa.Index("idx_raw_results_created_at", "created_at"),
    )

    # -- severity_snapshots --------------------------------------------------
    op.create_table(
        "severity_snapshots",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("image_id", sa.BigInteger, sa.ForeignKey("images.id", ondelete="CASCADE"), nullable=False),
        sa.Column("snapshot_date", sa.DateTime, nullable=False),
        sa.Column("critical_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("high_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("medium_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("low_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("total_open", sa.Integer, nullable=False, server_default="0"),
        sa.Column("newly_fixed", sa.Integer, nullable=False, server_default="0"),
        sa.UniqueConstraint("image_id", "snapshot_date", name="uq_image_date"),
        sa.Index("idx_snapshots_image_date", "image_id", "snapshot_date", unique=True),
        sa.Index("idx_snapshots_date", "snapshot_date"),
    )

    # -- security_policies ---------------------------------------------------
    op.create_table(
        "security_policies",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("policy_type",
                   sa.Enum("severity_threshold", "image_allowlist", "image_denylist",
                           "auto_remediate", "notification", "compliance", "retention",
                           name="policy_type"),
                   nullable=False),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("priority", sa.Integer, nullable=False, server_default="0"),
        sa.Column("rules", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("action",
                   sa.Enum("block", "alert", "auto_fix", "skip", "require_approval", "escalate",
                           name="policy_action"),
                   nullable=False, server_default="alert"),
        sa.Column("image_filters", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime, server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime, server_default=sa.text("now()"), nullable=False),
        sa.Column("created_by", sa.String(64), nullable=True),
        sa.Index("idx_policies_type", "policy_type"),
        sa.Index("idx_policies_enabled", "enabled"),
        sa.Index("idx_policies_priority", sa.text("priority DESC")),
    )

    # -- policy_evaluations --------------------------------------------------
    op.create_table(
        "policy_evaluations",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("policy_id", sa.BigInteger, sa.ForeignKey("security_policies.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("scan_id", sa.String(64), nullable=True),
        sa.Column("finding_id", sa.BigInteger,
                  sa.ForeignKey("scan_findings.id", ondelete="SET NULL"), nullable=True),
        sa.Column("evaluated_at", sa.DateTime, server_default=sa.text("now()"), nullable=False),
        sa.Column("violated", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("detail", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("action_taken",
                   sa.Enum("block", "alert", "auto_fix", "skip", "require_approval", "escalate",
                           name="policy_action"),
                   nullable=True),
        sa.Index("idx_evaluations_policy_id", "policy_id"),
        sa.Index("idx_evaluations_scan_id", "scan_id"),
        sa.Index("idx_evaluations_violated", "violated"),
    )

    # -- remediations --------------------------------------------------------
    op.create_table(
        "remediations",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("image_id", sa.BigInteger, sa.ForeignKey("images.id", ondelete="CASCADE"), nullable=False),
        sa.Column("status",
                   sa.Enum("pending", "analyzing", "patching", "building", "verifying",
                           "pr_opened", "completed", "failed", "skipped", "requires_review",
                           name="remediation_status"),
                   nullable=False, server_default="pending"),
        sa.Column("scan_id", sa.String(64), nullable=True),
        sa.Column("finding_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("target_severities", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("pr_url", sa.String(2048), nullable=True),
        sa.Column("pr_number", sa.Integer, nullable=True),
        sa.Column("branch_name", sa.String(512), nullable=True),
        sa.Column("verified", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("verification_findings_before", sa.Integer, nullable=False, server_default="0"),
        sa.Column("verification_findings_after", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime, server_default=sa.text("now()"), nullable=False),
        sa.Column("started_at", sa.DateTime, nullable=True),
        sa.Column("completed_at", sa.DateTime, nullable=True),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Index("idx_remediations_status", "status"),
        sa.Index("idx_remediations_image_id", "image_id"),
        sa.Index("idx_remediations_created_at", "created_at"),
    )

    # -- remediation_actions --------------------------------------------------
    op.create_table(
        "remediation_actions",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("remediation_id", sa.BigInteger,
                  sa.ForeignKey("remediations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("action_type",
                   sa.Enum("base_image_bump", "dependency_update", "config_change",
                           "package_removal", "custom",
                           name="remediation_action_type"),
                   nullable=False),
        sa.Column("file_path", sa.String(1024), nullable=True),
        sa.Column("before_value", sa.String(1024), nullable=True),
        sa.Column("after_value", sa.String(1024), nullable=True),
        sa.Column("success", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("detail", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime, server_default=sa.text("now()"), nullable=False),
        sa.Index("idx_remediation_actions_remediation_id", "remediation_id"),
        sa.Index("idx_remediation_actions_type", "action_type"),
    )

    # -- compliance_reports --------------------------------------------------
    op.create_table(
        "compliance_reports",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("report_format", sa.String(16), nullable=False),
        sa.Column("scope", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("generated_at", sa.DateTime, server_default=sa.text("now()"), nullable=False),
        sa.Column("file_path", sa.String(2048), nullable=True),
        sa.Column("summary", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("generated_by", sa.String(64), nullable=True),
        sa.Index("idx_compliance_reports_format", "report_format"),
        sa.Index("idx_compliance_reports_generated_at", "generated_at"),
    )

    # -- audit_log -----------------------------------------------------------
    op.create_table(
        "audit_log",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("timestamp", sa.DateTime, server_default=sa.text("now()"), nullable=False),
        sa.Column("event_type",
                   sa.Enum("scan_started", "scan_completed", "scan_failed",
                           "finding_created", "finding_closed",
                           "remediation_started", "remediation_completed", "remediation_failed",
                           "policy_created", "policy_updated", "policy_violated",
                           "compliance_report_generated",
                           "config_changed", "user_login", "system_error",
                           name="audit_event_type"),
                   nullable=False),
        sa.Column("entity_type", sa.String(64), nullable=True),
        sa.Column("entity_id", sa.String(128), nullable=True),
        sa.Column("image_id", sa.BigInteger,
                  sa.ForeignKey("images.id", ondelete="SET NULL"), nullable=True),
        sa.Column("detail", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("actor", sa.String(64), nullable=True),
        sa.Column("actor_kind", sa.String(16), nullable=True),
        sa.Index("idx_audit_event_type", "event_type"),
        sa.Index("idx_audit_timestamp", "timestamp"),
        sa.Index("idx_audit_image_id", "image_id"),
        sa.Index("idx_audit_entity", "entity_type", "entity_id"),
    )

    # -- container_runtime ---------------------------------------------------
    op.create_table(
        "container_runtime",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("container_id", sa.String(128), nullable=False),
        sa.Column("image_id", sa.BigInteger, sa.ForeignKey("images.id", ondelete="CASCADE"), nullable=False),
        sa.Column("timestamp", sa.DateTime, server_default=sa.text("now()"), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("severity", sa.Enum("critical", "high", "medium", "low", "unknown",
                                       name="severity"), nullable=True),
        sa.Column("detail", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("source", sa.String(128), nullable=True),
        sa.Index("idx_runtime_container_id", "container_id"),
        sa.Index("idx_runtime_image_id", "image_id"),
        sa.Index("idx_runtime_timestamp", "timestamp"),
        sa.Index("idx_runtime_event_type", "event_type"),
    )

    # -- Foreign key for remediations after table creation --------------------
    op.create_foreign_key(
        "fk_findings_remediation",
        "scan_findings", "remediations",
        ["remediation_id"], ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_table("container_runtime")
    op.drop_table("audit_log")
    op.drop_table("compliance_reports")
    op.drop_table("remediation_actions")
    op.drop_table("remediations")
    op.drop_table("policy_evaluations")
    op.drop_table("security_policies")
    op.drop_table("severity_snapshots")
    op.drop_table("raw_scan_results")
    op.drop_table("scan_findings")
    op.drop_table("scans")
    op.drop_table("images")

    # Drop enums
    for name in [
        "audit_event_type", "policy_action", "policy_type",
        "remediation_action_type", "remediation_status",
        "finding_source", "scan_status", "severity", "image_registry",
    ]:
        sa.Enum(name=name).drop(op.get_bind(), checkfirst=True)
