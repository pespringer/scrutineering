"""Add durable per-image scan schedules."""

from alembic import op
import sqlalchemy as sa

revision = "20261114_21"
down_revision = "20261114_20"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_schedules",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("image_id", sa.BigInteger(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("interval_seconds", sa.Integer(), nullable=False, server_default="21600"),
        sa.Column("next_run_at", sa.DateTime(), nullable=True),
        sa.Column("last_queued_at", sa.DateTime(), nullable=True),
        sa.Column("created_by", sa.String(length=128), nullable=False, server_default="system"),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["image_id"], ["images.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("image_id", name="uq_scan_schedules_image_id"),
    )
    op.create_index("idx_scan_schedules_next_run_at", "scan_schedules", ["next_run_at"])
    op.create_index("idx_scan_schedules_enabled", "scan_schedules", ["enabled"])


def downgrade() -> None:
    op.drop_index("idx_scan_schedules_enabled", table_name="scan_schedules")
    op.drop_index("idx_scan_schedules_next_run_at", table_name="scan_schedules")
    op.drop_table("scan_schedules")
