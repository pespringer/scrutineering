"""Persist remediation verification scan correlation and result."""

from alembic import op
import sqlalchemy as sa


revision = "20261114_25"
down_revision = "20261114_24"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("remediations", sa.Column("verification_scan_id", sa.String(length=64), nullable=True))
    op.add_column("remediations", sa.Column("verification_status", sa.String(length=32), nullable=False, server_default="not_requested"))
    op.add_column("remediations", sa.Column("verification_error", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("remediations", "verification_error")
    op.drop_column("remediations", "verification_status")
    op.drop_column("remediations", "verification_scan_id")
