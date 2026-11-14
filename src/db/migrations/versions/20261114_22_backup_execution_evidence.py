"""Persist backup artifact observations for operational readiness."""

from alembic import op
import sqlalchemy as sa


revision = "20261114_22"
down_revision = "20261114_21"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "backup_executions",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("artifact_name", sa.String(length=512), nullable=False),
        sa.Column("source", sa.String(length=128), nullable=False, server_default="postgres"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="observed"),
        sa.Column("artifact_created_at", sa.DateTime(), nullable=False),
        sa.Column("observed_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("verified", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("sha256", sa.String(length=64), nullable=True),
        sa.Column("manifest", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("recorded_by", sa.String(length=128), nullable=False, server_default="backup-scheduler"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("artifact_name", "artifact_created_at", name="uq_backup_artifact_observation"),
    )
    op.create_index("idx_backup_executions_observed_at", "backup_executions", ["observed_at"])
    op.create_index("idx_backup_executions_status", "backup_executions", ["status"])


def downgrade() -> None:
    op.drop_index("idx_backup_executions_status", table_name="backup_executions")
    op.drop_index("idx_backup_executions_observed_at", table_name="backup_executions")
    op.drop_table("backup_executions")
