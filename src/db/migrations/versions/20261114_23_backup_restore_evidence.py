"""Persist isolated backup restore verification evidence."""

from alembic import op
import sqlalchemy as sa


revision = "20261114_23"
down_revision = "20261114_22"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "backup_restore_executions",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("backup_execution_id", sa.BigInteger(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="queued"),
        sa.Column("target_database", sa.String(length=128), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("duration_seconds", sa.Float(), nullable=True),
        sa.Column("table_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("row_counts", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("cleanup_verified", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("manifest", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("recorded_by", sa.String(length=128), nullable=False, server_default="restore-worker"),
        sa.ForeignKeyConstraint(["backup_execution_id"], ["backup_executions.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_backup_restore_executions_backup", "backup_restore_executions", ["backup_execution_id"])
    op.create_index("idx_backup_restore_executions_status", "backup_restore_executions", ["status"])
    op.create_index("idx_backup_restore_executions_started_at", "backup_restore_executions", ["started_at"])


def downgrade() -> None:
    op.drop_index("idx_backup_restore_executions_started_at", table_name="backup_restore_executions")
    op.drop_index("idx_backup_restore_executions_status", table_name="backup_restore_executions")
    op.drop_index("idx_backup_restore_executions_backup", table_name="backup_restore_executions")
    op.drop_table("backup_restore_executions")
