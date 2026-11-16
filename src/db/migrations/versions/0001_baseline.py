"""Baseline schema.

Replaces the 28 pre-reset migrations (squashed in reset Phase 1d; the old chain
is in the pre-reset-2026-11 tag). Databases created before the squash must be
recreated: see docs/RESET-PLAN.md, Phase 1d.

Revision ID: 0001_baseline
Revises:
Create Date: 2026-11-16 03:01:56.390552
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0001_baseline'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('images',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('registry', sa.Enum('dockerhub', 'gcr', 'ecr', 'ghcr', 'gitlab', 'harbor', 'quay', 'other', name='imageregistry'), nullable=False),
    sa.Column('repo_name', sa.String(length=512), nullable=False),
    sa.Column('tag', sa.String(length=256), nullable=False),
    sa.Column('digest', sa.String(length=128), nullable=True),
    sa.Column('discovered_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
    sa.Column('last_scan_id', sa.String(length=64), nullable=True),
    sa.Column('last_scan_at', sa.DateTime(), nullable=True),
    sa.Column('active', sa.Boolean(), nullable=False),
    sa.Column('labels', sa.JSON(), nullable=False),
    sa.CheckConstraint('char_length(repo_name) <= 512', name='chk_images_repo_length'),
    sa.CheckConstraint('char_length(tag) <= 256', name='chk_images_tag_length'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('registry', 'repo_name', 'tag', name='uq_image_registry_repo_tag')
    )
    op.create_index('idx_images_name', 'images', ['repo_name'], unique=False)
    op.create_index('idx_images_registry', 'images', ['registry'], unique=False)
    op.create_index('idx_images_tag', 'images', ['tag'], unique=False)
    op.create_table('audit_log',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('timestamp', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
    sa.Column('event_type', sa.Enum('scan_started', 'scan_completed', 'scan_failed', 'scan_cancelled', 'finding_created', 'finding_closed', 'remediation_started', 'remediation_completed', 'remediation_failed', 'policy_created', 'policy_updated', 'policy_violated', 'compliance_report_generated', 'config_changed', 'user_login', 'system_error', name='auditeventtype'), nullable=False),
    sa.Column('entity_type', sa.String(length=64), nullable=True),
    sa.Column('entity_id', sa.String(length=128), nullable=True),
    sa.Column('image_id', sa.BigInteger(), nullable=True),
    sa.Column('detail', sa.JSON(), nullable=False),
    sa.Column('previous_hash', sa.String(length=64), nullable=True),
    sa.Column('record_hash', sa.String(length=64), nullable=True),
    sa.Column('actor', sa.String(length=64), nullable=True),
    sa.Column('actor_kind', sa.String(length=16), nullable=True),
    sa.ForeignKeyConstraint(['image_id'], ['images.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_audit_entity_id', 'audit_log', ['entity_type', 'entity_id'], unique=False)
    op.create_index('idx_audit_event_type', 'audit_log', ['event_type'], unique=False)
    op.create_index('idx_audit_image_id', 'audit_log', ['image_id'], unique=False)
    op.create_index('idx_audit_timestamp', 'audit_log', ['timestamp'], unique=False)
    op.create_index(op.f('ix_audit_log_record_hash'), 'audit_log', ['record_hash'], unique=False)
    op.create_table('remediations',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('image_id', sa.BigInteger(), nullable=False),
    sa.Column('status', sa.Enum('pending', 'analyzing', 'patching', 'building', 'verifying', 'pr_opened', 'completed', 'failed', 'skipped', 'requires_review', name='remediationstatus'), nullable=False),
    sa.Column('scan_id', sa.String(length=64), nullable=True),
    sa.Column('finding_count', sa.Integer(), nullable=False),
    sa.Column('target_severities', sa.JSON(), nullable=False),
    sa.Column('pr_url', sa.String(length=2048), nullable=True),
    sa.Column('pr_number', sa.Integer(), nullable=True),
    sa.Column('branch_name', sa.String(length=512), nullable=True),
    sa.Column('verified', sa.Boolean(), nullable=False),
    sa.Column('approved_by', sa.String(length=128), nullable=True),
    sa.Column('approved_at', sa.DateTime(), nullable=True),
    sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
    sa.Column('started_at', sa.DateTime(), nullable=True),
    sa.Column('completed_at', sa.DateTime(), nullable=True),
    sa.Column('error_message', sa.Text(), nullable=True),
    sa.ForeignKeyConstraint(['image_id'], ['images.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_remediations_approved_by', 'remediations', ['approved_by'], unique=False)
    op.create_index('idx_remediations_created_at', 'remediations', ['created_at'], unique=False)
    op.create_index('idx_remediations_image_id', 'remediations', ['image_id'], unique=False)
    op.create_index('idx_remediations_status', 'remediations', ['status'], unique=False)
    op.create_table('scans',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('scan_id', sa.String(length=64), nullable=False),
    sa.Column('image_id', sa.BigInteger(), nullable=False),
    sa.Column('started_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
    sa.Column('completed_at', sa.DateTime(), nullable=True),
    sa.Column('duration_seconds', sa.Float(), nullable=True),
    sa.Column('image_digest', sa.String(length=128), nullable=True),
    sa.Column('scanner_versions', sa.JSON(), nullable=False),
    sa.Column('vulnerability_db_versions', sa.JSON(), nullable=False),
    sa.Column('status', sa.Enum('pending', 'running', 'completed', 'partial', 'failed', 'cancelled', name='scanstatus'), nullable=False),
    sa.Column('phase', sa.String(length=64), nullable=False),
    sa.Column('task_id', sa.String(length=64), nullable=True),
    sa.Column('total_findings', sa.Integer(), nullable=False),
    sa.Column('critical_count', sa.Integer(), nullable=False),
    sa.Column('high_count', sa.Integer(), nullable=False),
    sa.Column('medium_count', sa.Integer(), nullable=False),
    sa.Column('low_count', sa.Integer(), nullable=False),
    sa.Column('error_message', sa.Text(), nullable=True),
    sa.Column('archived', sa.Boolean(), nullable=False),
    sa.Column('scheduler_type', sa.String(length=32), nullable=True),
    sa.CheckConstraint('char_length(scan_id) <= 64', name='chk_scans_id_length'),
    sa.ForeignKeyConstraint(['image_id'], ['images.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('scan_id')
    )
    op.create_index('idx_scans_image_id', 'scans', ['image_id'], unique=False)
    op.create_index('idx_scans_image_status', 'scans', ['image_id', 'status'], unique=False)
    op.create_index('idx_scans_started_at', 'scans', ['started_at'], unique=False)
    op.create_index('idx_scans_status', 'scans', ['status'], unique=False)
    op.create_table('severity_snapshots',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('image_id', sa.BigInteger(), nullable=False),
    sa.Column('snapshot_date', sa.DateTime(), nullable=False),
    sa.Column('critical_count', sa.Integer(), nullable=False),
    sa.Column('high_count', sa.Integer(), nullable=False),
    sa.Column('medium_count', sa.Integer(), nullable=False),
    sa.Column('low_count', sa.Integer(), nullable=False),
    sa.Column('total_open', sa.Integer(), nullable=False),
    sa.Column('newly_fixed', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['image_id'], ['images.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('image_id', 'snapshot_date', name='uq_image_date')
    )
    op.create_index('idx_snapshots_date', 'severity_snapshots', ['snapshot_date'], unique=False)
    op.create_index('idx_snapshots_image_date', 'severity_snapshots', ['image_id', 'snapshot_date'], unique=True)
    op.create_table('remediation_actions',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('remediation_id', sa.BigInteger(), nullable=False),
    sa.Column('action_type', sa.Enum('base_image_bump', 'dependency_update', 'config_change', 'package_removal', 'custom', name='remediationactiontype'), nullable=False),
    sa.Column('file_path', sa.String(length=1024), nullable=True),
    sa.Column('before_value', sa.String(length=1024), nullable=True),
    sa.Column('after_value', sa.String(length=1024), nullable=True),
    sa.Column('success', sa.Boolean(), nullable=False),
    sa.Column('detail', sa.JSON(), nullable=False),
    sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['remediation_id'], ['remediations.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_remediation_actions_remediation_id', 'remediation_actions', ['remediation_id'], unique=False)
    op.create_index('idx_remediation_actions_type', 'remediation_actions', ['action_type'], unique=False)
    op.create_table('remediation_events',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('remediation_id', sa.BigInteger(), nullable=False),
    sa.Column('event_type', sa.String(length=64), nullable=False),
    sa.Column('sequence', sa.Integer(), nullable=True),
    sa.Column('detail', sa.JSON(), nullable=False),
    sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['remediation_id'], ['remediations.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_remediation_events_remediation_id', 'remediation_events', ['remediation_id'], unique=False)
    op.create_index('idx_remediation_events_sequence', 'remediation_events', ['remediation_id', 'sequence'], unique=False)
    op.create_table('remediation_publications',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('remediation_id', sa.BigInteger(), nullable=False),
    sa.Column('provider', sa.String(length=32), nullable=False),
    sa.Column('repository', sa.String(length=256), nullable=False),
    sa.Column('idempotency_key', sa.String(length=256), nullable=False),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('url', sa.String(length=2048), nullable=True),
    sa.Column('provider_number', sa.Integer(), nullable=True),
    sa.Column('request_hash', sa.String(length=64), nullable=False),
    sa.Column('error_message', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
    sa.Column('completed_at', sa.DateTime(), nullable=True),
    sa.Column('merged_at', sa.DateTime(), nullable=True),
    sa.Column('merge_commit', sa.String(length=64), nullable=True),
    sa.Column('observed_digest', sa.String(length=71), nullable=True),
    sa.Column('verification_status', sa.String(length=32), nullable=True),
    sa.Column('verification_detail', sa.JSON(), nullable=False),
    sa.Column('scan_status', sa.String(length=32), nullable=True),
    sa.Column('post_merge_scan_id', sa.String(length=64), nullable=True),
    sa.Column('findings_before', sa.Integer(), nullable=True),
    sa.Column('findings_after', sa.Integer(), nullable=True),
    sa.Column('rollback_command', sa.JSON(), nullable=False),
    sa.ForeignKeyConstraint(['remediation_id'], ['remediations.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('provider', 'repository', 'idempotency_key', name='uq_remediation_publication_key')
    )
    op.create_index('idx_remediation_publications_remediation_id', 'remediation_publications', ['remediation_id'], unique=False)
    op.create_index('idx_remediation_publications_status', 'remediation_publications', ['status'], unique=False)
    op.create_table('remediation_webhook_events',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('remediation_id', sa.BigInteger(), nullable=True),
    sa.Column('provider', sa.String(length=32), nullable=False),
    sa.Column('event_id', sa.String(length=256), nullable=False),
    sa.Column('event_type', sa.String(length=64), nullable=False),
    sa.Column('received_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['remediation_id'], ['remediations.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('provider', 'event_id', name='uq_remediation_webhook_event')
    )
    op.create_index('idx_remediation_webhook_events_remediation_id', 'remediation_webhook_events', ['remediation_id'], unique=False)
    op.create_table('scan_findings',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('scan_id', sa.String(length=64), nullable=True),
    sa.Column('image_id', sa.BigInteger(), nullable=False),
    sa.Column('fingerprint', sa.String(length=128), nullable=False),
    sa.Column('package_name', sa.String(length=256), nullable=False),
    sa.Column('package_version', sa.String(length=64), nullable=True),
    sa.Column('package_type', sa.String(length=64), nullable=True),
    sa.Column('file_path', sa.String(length=1024), nullable=True),
    sa.Column('cve_id', sa.String(length=32), nullable=True),
    sa.Column('title', sa.String(length=1024), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('severity', sa.Enum('critical', 'high', 'medium', 'low', 'unknown', name='severity'), nullable=True),
    sa.Column('source', sa.Enum('trivy', 'grype', name='findingsource'), nullable=False),
    sa.Column('scanner_version', sa.String(length=64), nullable=True),
    sa.Column('vulnerability_db_version', sa.String(length=128), nullable=True),
    sa.Column('fixed_version', sa.String(length=64), nullable=True),
    sa.Column('fix_available', sa.Boolean(), nullable=False),
    sa.Column('first_seen', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
    sa.Column('last_seen', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
    sa.Column('remediated', sa.Boolean(), nullable=False),
    sa.Column('resolved_at', sa.DateTime(), nullable=True),
    sa.Column('reopened_at', sa.DateTime(), nullable=True),
    sa.Column('acknowledged', sa.Boolean(), nullable=False),
    sa.Column('assigned_to', sa.String(length=128), nullable=True),
    sa.Column('remediation_id', sa.BigInteger(), nullable=True),
    sa.CheckConstraint('char_length(fingerprint) <= 128', name='chk_findings_fingerprint_length'),
    sa.ForeignKeyConstraint(['image_id'], ['images.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['remediation_id'], ['remediations.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('fingerprint', 'image_id', name='uq_fingerprint_image')
    )
    op.create_index('idx_findings_cve_image', 'scan_findings', ['cve_id', 'image_id'], unique=False)
    op.create_index('idx_findings_fingerprint', 'scan_findings', ['fingerprint'], unique=False)
    op.create_index('idx_findings_first_seen', 'scan_findings', ['first_seen'], unique=False)
    op.create_index('idx_findings_image_id', 'scan_findings', ['image_id'], unique=False)
    op.create_index('idx_findings_remediated', 'scan_findings', ['remediated'], unique=False)
    op.create_index('idx_findings_resolved_at', 'scan_findings', ['resolved_at'], unique=False)
    op.create_index('idx_findings_severity', 'scan_findings', ['severity'], unique=False)


def downgrade() -> None:
    op.drop_index('idx_findings_severity', table_name='scan_findings')
    op.drop_index('idx_findings_resolved_at', table_name='scan_findings')
    op.drop_index('idx_findings_remediated', table_name='scan_findings')
    op.drop_index('idx_findings_image_id', table_name='scan_findings')
    op.drop_index('idx_findings_first_seen', table_name='scan_findings')
    op.drop_index('idx_findings_fingerprint', table_name='scan_findings')
    op.drop_index('idx_findings_cve_image', table_name='scan_findings')
    op.drop_table('scan_findings')
    op.drop_index('idx_remediation_webhook_events_remediation_id', table_name='remediation_webhook_events')
    op.drop_table('remediation_webhook_events')
    op.drop_index('idx_remediation_publications_status', table_name='remediation_publications')
    op.drop_index('idx_remediation_publications_remediation_id', table_name='remediation_publications')
    op.drop_table('remediation_publications')
    op.drop_index('idx_remediation_events_sequence', table_name='remediation_events')
    op.drop_index('idx_remediation_events_remediation_id', table_name='remediation_events')
    op.drop_table('remediation_events')
    op.drop_index('idx_remediation_actions_type', table_name='remediation_actions')
    op.drop_index('idx_remediation_actions_remediation_id', table_name='remediation_actions')
    op.drop_table('remediation_actions')
    op.drop_index('idx_snapshots_image_date', table_name='severity_snapshots')
    op.drop_index('idx_snapshots_date', table_name='severity_snapshots')
    op.drop_table('severity_snapshots')
    op.drop_index('idx_scans_status', table_name='scans')
    op.drop_index('idx_scans_started_at', table_name='scans')
    op.drop_index('idx_scans_image_status', table_name='scans')
    op.drop_index('idx_scans_image_id', table_name='scans')
    op.drop_table('scans')
    op.drop_index('idx_remediations_status', table_name='remediations')
    op.drop_index('idx_remediations_image_id', table_name='remediations')
    op.drop_index('idx_remediations_created_at', table_name='remediations')
    op.drop_index('idx_remediations_approved_by', table_name='remediations')
    op.drop_table('remediations')
    op.drop_index(op.f('ix_audit_log_record_hash'), table_name='audit_log')
    op.drop_index('idx_audit_timestamp', table_name='audit_log')
    op.drop_index('idx_audit_image_id', table_name='audit_log')
    op.drop_index('idx_audit_event_type', table_name='audit_log')
    op.drop_index('idx_audit_entity_id', table_name='audit_log')
    op.drop_table('audit_log')
    op.drop_index('idx_images_tag', table_name='images')
    op.drop_index('idx_images_registry', table_name='images')
    op.drop_index('idx_images_name', table_name='images')
    op.drop_table('images')
    for enum_name in (
        "findingsource", "severity", "remediationactiontype", "scanstatus",
        "remediationstatus", "auditeventtype", "imageregistry",
    ):
        sa.Enum(name=enum_name).drop(op.get_bind(), checkfirst=True)
