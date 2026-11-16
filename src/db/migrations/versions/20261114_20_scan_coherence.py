"""Persist scan progress details for operator visibility."""

from alembic import op
import sqlalchemy as sa

revision = "20261114_20"
down_revision = "20261114_19"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("phase", sa.String(length=64), nullable=True))
    op.add_column("scans", sa.Column("task_id", sa.String(length=64), nullable=True))
    op.execute("UPDATE scans SET phase = CASE WHEN status IN ('completed', 'partial', 'failed', 'cancelled') THEN status ELSE 'queued' END")
    op.alter_column("scans", "phase", nullable=False, server_default="queued")
    op.create_index("idx_scans_task_id", "scans", ["task_id"])


def downgrade() -> None:
    op.drop_index("idx_scans_task_id", table_name="scans")
    op.drop_column("scans", "task_id")
    op.drop_column("scans", "phase")
