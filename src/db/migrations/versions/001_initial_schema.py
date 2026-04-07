"""Initial migration — create all Container Sentinel tables.

Tables created:
  images              — Container images tracked by Sentinel
  scans               — Individual scan execution records
  scan_findings       — Deduplicated vulnerability findings
  raw_scan_results    — Raw scanner JSON output for audit
  severity_snapshots  — Daily severity count snapshots for trends
  security_policies   — User-defined security policies
  policy_evaluations  — Policy evaluation audit log
  remediations        — Remediation effort lifecycle
  remediation_actions — Individual actions within a remediation
  compliance_reports  — Generated compliance report metadata
  audit_log           — Append-only security and system event log
  container_runtime   — Runtime behaviour monitoring data

Revision ID: initial_schema
Revises: (create_revision)
Create Date: 2026-04-05

"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "initial_schema"
down_revision = None  # type: ignore
branch_labels = None  # type: ignore
depends_on = None  # type: ignore

# Enums as PostgreSQL ENUM types
severity_enum = postgresql.ENUM(
    "critical", "high", "medium", "low", "unknown",
    name="severity", create_type=True,
)

finding_source_enum = postgresql.ENUM(
    "trivy", "grype",
    name="findingsource", create_type=True,
)

image_registry_enum = postgresql.ENUM(
    "dockerhub", "gcr", "ecr", "ghcr", "gitlab", "harbor", "quay", "other",
    name="imageregistry", create_type=True,
)

scan_status_enum = postgresql.ENUM(
    "pending", "running", "completed", "failed", "cancelled",
    name="scanstatus", create_type=True,
)

remediation_status_enum = postgresql.ENUM(
    "pending", "analyzing", "patching", "building", "verifying",
    "pr_opened", "completed", "failed", "skipped", "requires_review",
    name="remediationstatus", create_type=True,
)

remediation_action_type_enum = postgresql.ENUM(
    "base_image_bump", "dependency_update", "config_change",
    "package_removal", "custom",
    name="remediationactiontype", create_type=True,
)

policy_type_enum = postgresql.ENUM(
    "severity_threshold", "image_allowlist", "image_denylist",
    "auto_remediate", "notification", "compliance", "retention",
    name="policytype", create_type=True,
)

policy_action_enum = postgresql.ENUM(
    "block", "alert", "auto_fix", "skip", "require_approval", "escalate",
    name="policyaction", create_type=True,
)

audit_event_type_enum = postgresql.ENUM(
    "scan_started", "scan_completed", "scan_failed",
    "finding_created", "finding_closed",
    "remediation_started", "remediation_completed", "remediation_failed",
    "policy_created", "policy_updated", "policy_violated",
    "compliance_report_generated",
    "config_changed", "user_login", "system_error",
    name="auditeventtype", create_type=True,
)


def upgrade() -> None:
    # -- Enum types ---------------------------------------------------------
    severity_enum.create(op.get_bind())
    finding_source_enum.create(op.get_bind())
    image_registry_enum.create(op.get_bind())
    scan_status_enum.create(op.get_bind())
    remediation_status_enum.create(op.get_bind())
    remediation_action_type_enum.create(op.get_bind())
    policy_type_enum.create(op.get_bind())
    policy_action_enum.create(op.get_bind())
    audit_event_type_enum.create(op.get_bind())

    # -- images -------------------------------------------------------------
    op.create_table(
        "images",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("registry", image_registry_enum, nullable=False,
                  server_default="dockerhub"),
        sa.Column("repo_name", sa.String(512), nullable=False),
        sa.Column("tag", sa.String(256), nullable=False, server_default="latest"),
        sa.Column("digest", sa.String(128), nullable=True),
        sa.Column("discovered_at", sa.DateTime,
                  server_default=sa.func.now()),
        sa.Column("last_scan_id", sa.String(64), nullable=True),
        sa.Column("last_scan_at", sa.DateTime, nullable=True),
        sa.Column("active", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("labels", postgresql.JSONB, nullable=False,
                  server_default="{}"),
        sa.CheckConstraint("char_length(registry) <= 32",
                           name="chk_images_registry_length"),
        sa.CheckConstraint("char_length(repo_name) <= 512",
                           name="chk_images_repo_length"),
        sa.CheckConstraint("char_length(tag) <= 256",
                           name="chk_images_tag_length"),
    )
    op.create_index("idx_images_registry", "images", ["registry"])
    op.create_index("idx_images_name", "images", ["repo_name"])
    op.create_index("idx_images_tag", "images", ["tag"])
    op.create_unique_constraint("uq_image_registry_repo_tag", "images",
                                ["registry", "repo_name", "tag"])

    # -- scans --------------------------------------------------------------
    op.create_table(
        "scans",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("scan_id", sa.String(64), nullable=False, unique=True),
        sa.Column("image_id", sa.BigInteger, sa.ForeignKey(
            "images.id", ondelete="CASCADE"), nullable=False),
        sa.Column("started_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime, nullable=True),
        sa.Column("duration_seconds", sa.Float, nullable=True),
        sa.Column("status", scan_status_enum, nullable=False,
                  server_default="pending"),
        sa.Column("total_findings", sa.Integer, nullable=False,
                  server_default="0"),
        sa.Column("critical_count", sa.Integer, nullable=False,
                  server_default="0"),
        sa.Column("high_count", sa.Integer, nullable=False,
                  server_default="0"),
        sa.Column("medium_count", sa.Integer, nullable=False,
                  server_default="0"),
        sa.Column("low_count", sa.Integer, nullable=False,
                  server_default="0"),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("scheduler_type", sa.String(32), nullable=True),
        sa.CheckConstraint("char_length(scan_id) <= 64",
                           name="chk_scans_id_length"),
    )
    op.create_index("idx_scans_image_id", "scans", ["image_id"])
    op.create_index("idx_scans_status", "scans", ["status"])
    op.create_index("idx_scans_started_at", "scans", ["started_at"])
    op.create_index("idx_scans_image_status", "scans", ["image_id", "status"])

    # -- scan_findings ------------------------------------------------------
    op.create_table(
        "scan_findings",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("scan_id", sa.String(64), nullable=True),
        sa.Column("image_id", sa.BigInteger, sa.ForeignKey(
            "images.id", ondelete="CASCADE"), nullable=False),
        sa.Column("fingerprint", sa.String(128), nullable=False),
        sa.Column("package_name", sa.String(256), nullable=False),
        sa.Column("package_version", sa.String(64), nullable=True),
        sa.Column("package_type", sa.String(64), nullable=True),
        sa.Column("cve_id", sa.String(32), nullable=True),
        sa.Column("title", sa.String(1024), nullable=False, server_default=""),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("severity", severity_enum, nullable=True),
        sa.Column("source", finding_source_enum, nullable=False),
        sa.Column("scanner_version", sa.String(64), nullable=True),
        sa.Column("fixed_version", sa.String(64), nullable=True),
        sa.Column("fix_available", sa.Boolean, nullable=False,
                  server_default="false"),
        sa.Column("first_seen", sa.DateTime, server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime, server_default=sa.func.now()),
        sa.Column("remediated", sa.Boolean, nullable=False,
                  server_default="false"),
        sa.Column("remediation_id", sa.BigInteger, nullable=True),
        sa.CheckConstraint("char_length(fingerprint) <= 128",
                           name="chk_findings_fingerprint_length"),
    )
    op.create_index("idx_findings_image_id", "scan_findings", ["image_id"])
    op.create_index("idx_findings_severity", "scan_findings", ["severity"])
    op.create_index("idx_findings_fingerprint", "scan_findings",
                    ["fingerprint"])
    op.create_index("idx_findings_first_seen", "scan_findings",
                    ["first_seen"])
    op.create_index("idx_findings_remediated", "scan_findings",
                    ["remediated"])
    op.create_index("idx_findings_cve_image", "scan_findings",
                    ["cve_id", "image_id"])
    op.create_unique_constraint("uq_fingerprint_image", "scan_findings",
                                ["fingerprint", "image_id"])

    # -- raw_scan_results ---------------------------------------------------
    op.create_table(
        "raw_scan_results",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("image_id", sa.BigInteger, sa.ForeignKey(
            "images.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_id", sa.String(64), nullable=False),
        sa.Column("scanner_source", finding_source_enum, nullable=False),
        sa.Column("raw_output", postgresql.JSONB, nullable=False),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("file_size_bytes", sa.BigInteger, nullable=True),
    )
    op.create_index("idx_raw_results_image_id", "raw_scan_results",
                    ["image_id"])
    op.create_index("idx_raw_results_scanner", "raw_scan_results",
                    ["scanner_source"])
    op.create_index("idx_raw_results_scan_id", "raw_scan_results",
                    ["scan_id"])
    op.create_index("idx_raw_results_created_at", "raw_scan_results",
                    ["created_at"])

    # -- severity_snapshots -------------------------------------------------
    op.create_table(
        "severity_snapshots",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("image_id", sa.BigInteger, sa.ForeignKey(
            "images.id", ondelete="CASCADE"), nullable=False),
        sa.Column("snapshot_date", sa.DateTime, nullable=False),
        sa.Column("critical_count", sa.Integer, nullable=False,
                  server_default="0"),
        sa.Column("high_count", sa.Integer, nullable=False,
                  server_default="0"),
        sa.Column("medium_count", sa.Integer, nullable=False,
                  server_default="0"),
        sa.Column("low_count", sa.Integer, nullable=False,
                  server_default="0"),
        sa.Column("total_open", sa.Integer, nullable=False,
                  server_default="0"),
        sa.Column("newly_fixed", sa.Integer, nullable=False,
                  server_default="0"),
    )
    op.create_index("idx_snapshots_image_date", "severity_snapshots",
                    ["image_id", "snapshot_date"], unique=True)
    op.create_index("idx_snapshots_date", "severity_snapshots",
                    ["snapshot_date"])
    op.create_unique_constraint("uq_image_date", "severity_snapshots",
                                ["image_id", "snapshot_date"])

    # -- security_policies --------------------------------------------------
    op.create_table(
        "security_policies",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("policy_type", policy_type_enum, nullable=False),
        sa.Column("enabled", sa.Boolean, nullable=False,
                  server_default="true"),
        sa.Column("priority", sa.Integer, nullable=False,
                  server_default="0"),
        sa.Column("rules", postgresql.JSONB, nullable=False,
                  server_default="{}"),
        sa.Column("action", policy_action_enum, nullable=False,
                  server_default="alert"),
        sa.Column("image_filters", postgresql.JSONB, nullable=False,
                  server_default="{}"),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(64), nullable=True),
    )
    op.create_index("idx_policies_type", "security_policies", ["policy_type"])
    op.create_index("idx_policies_enabled", "security_policies", ["enabled"])
    op.create_index("idx_policies_priority", "security_policies",
                    ["priority"])

    # -- policy_evaluations -------------------------------------------------
    op.create_table(
        "policy_evaluations",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("policy_id", sa.BigInteger, sa.ForeignKey(
            "security_policies.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_id", sa.String(64), nullable=True),
        sa.Column("finding_id", sa.BigInteger, sa.ForeignKey(
            "scan_findings.id", ondelete="SET NULL"), nullable=True),
        sa.Column("evaluated_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("violated", sa.Boolean, nullable=False,
                  server_default="false"),
        sa.Column("detail", postgresql.JSONB, nullable=False,
                  server_default="{}"),
        sa.Column("action_taken", policy_action_enum, nullable=True),
    )
    op.create_index("idx_evaluations_policy_id", "policy_evaluations",
                    ["policy_id"])
    op.create_index("idx_evaluations_scan_id", "policy_evaluations",
                    ["scan_id"])
    op.create_index("idx_evaluations_violated", "policy_evaluations",
                    ["violated"])

    # -- remediations -------------------------------------------------------
    op.create_table(
        "remediations",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("image_id", sa.BigInteger, sa.ForeignKey(
            "images.id", ondelete="CASCADE"), nullable=False),
        sa.Column("status", remediation_status_enum, nullable=False,
                  server_default="pending"),
        sa.Column("scan_id", sa.String(64), nullable=True),
        sa.Column("finding_count", sa.Integer, nullable=False,
                  server_default="0"),
        sa.Column("target_severities", postgresql.JSONB, nullable=False,
                  server_default="{}"),
        sa.Column("pr_url", sa.String(2048), nullable=True),
        sa.Column("pr_number", sa.Integer, nullable=True),
        sa.Column("branch_name", sa.String(512), nullable=True),
        sa.Column("verified", sa.Boolean, nullable=False,
                  server_default="false"),
        sa.Column("verification_findings_before", sa.Integer, nullable=False,
                  server_default="0"),
        sa.Column("verification_findings_after", sa.Integer, nullable=False,
                  server_default="0"),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime, nullable=True),
        sa.Column("completed_at", sa.DateTime, nullable=True),
        sa.Column("error_message", sa.Text, nullable=True),
    )
    op.create_index("idx_remediations_status", "remediations", ["status"])
    op.create_index("idx_remediations_image_id", "remediations", ["image_id"])
    op.create_index("idx_remediations_created_at", "remediations",
                    ["created_at"])

    # -- remediation_actions ------------------------------------------------
    op.create_table(
        "remediation_actions",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("remediation_id", sa.BigInteger, sa.ForeignKey(
            "remediations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("action_type", remediation_action_type_enum, nullable=False),
        sa.Column("file_path", sa.String(1024), nullable=True),
        sa.Column("before_value", sa.String(1024), nullable=True),
        sa.Column("after_value", sa.String(1024), nullable=True),
        sa.Column("success", sa.Boolean, nullable=False,
                  server_default="false"),
        sa.Column("detail", postgresql.JSONB, nullable=False,
                  server_default="{}"),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
    )
    op.create_index("idx_remediation_actions_remediation_id",
                    "remediation_actions", ["remediation_id"])
    op.create_index("idx_remediation_actions_type", "remediation_actions",
                    ["action_type"])

    # -- compliance_reports -------------------------------------------------
    op.create_table(
        "compliance_reports",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("report_format", sa.String(16), nullable=False),
        sa.Column("scope", postgresql.JSONB, nullable=False,
                  server_default="{}"),
        sa.Column("generated_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("file_path", sa.String(2048), nullable=True),
        sa.Column("summary", postgresql.JSONB, nullable=False,
                  server_default="{}"),
        sa.Column("generated_by", sa.String(64), nullable=True),
    )
    op.create_index("idx_compliance_reports_format", "compliance_reports",
                    ["report_format"])
    op.create_index("idx_compliance_reports_generated_at",
                    "compliance_reports", ["generated_at"])

    # -- audit_log ----------------------------------------------------------
    op.create_table(
        "audit_log",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("timestamp", sa.DateTime, server_default=sa.func.now(),
                  nullable=False),
        sa.Column("event_type", audit_event_type_enum, nullable=False),
        sa.Column("entity_type", sa.String(64), nullable=True),
        sa.Column("entity_id", sa.String(128), nullable=True),
        sa.Column("image_id", sa.BigInteger, sa.ForeignKey(
            "images.id", ondelete="SET NULL"), nullable=True),
        sa.Column("detail", postgresql.JSONB, nullable=False,
                  server_default="{}"),
        sa.Column("actor", sa.String(64), nullable=True),
        sa.Column("actor_kind", sa.String(16), nullable=True),
    )
    op.create_index("idx_audit_event_type", "audit_log", ["event_type"])
    op.create_index("idx_audit_timestamp", "audit_log", ["timestamp"])
    op.create_index("idx_audit_image_id", "audit_log", ["image_id"])
    op.create_index("idx_audit_entity_id", "audit_log",
                    ["entity_type", "entity_id"])

    # -- container_runtime --------------------------------------------------
    op.create_table(
        "container_runtime",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("container_id", sa.String(128), nullable=False),
        sa.Column("image_id", sa.BigInteger, sa.ForeignKey(
            "images.id", ondelete="CASCADE"), nullable=False),
        sa.Column("timestamp", sa.DateTime, server_default=sa.func.now(),
                  nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("severity", severity_enum, nullable=True),
        sa.Column("detail", postgresql.JSONB, nullable=False,
                  server_default="{}"),
        sa.Column("source", sa.String(128), nullable=True),
    )
    op.create_index("idx_runtime_container_id", "container_runtime",
                    ["container_id"])
    op.create_index("idx_runtime_image_id", "container_runtime", ["image_id"])
    op.create_index("idx_runtime_timestamp", "container_runtime",
                    ["timestamp"])
    op.create_index("idx_runtime_event_type", "container_runtime",
                    ["event_type"])

    # -- FK for scan_findings -> remediations (created after both tables) ---
    op.create_foreign_key(
        "fk_findings_remediation",
        "scan_findings", "remediations",
        ["remediation_id"], ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    # Drop tables in reverse dependency order
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
    audit_event_type_enum.drop(op.get_bind(), checkfirst=True)
    policy_action_enum.drop(op.get_bind(), checkfirst=True)
    policy_type_enum.drop(op.get_bind(), checkfirst=True)
    remediation_action_type_enum.drop(op.get_bind(), checkfirst=True)
    remediation_status_enum.drop(op.get_bind(), checkfirst=True)
    scan_status_enum.drop(op.get_bind(), checkfirst=True)
    image_registry_enum.drop(op.get_bind(), checkfirst=True)
    finding_source_enum.drop(op.get_bind(), checkfirst=True)
    severity_enum.drop(op.get_bind(), checkfirst=True)
