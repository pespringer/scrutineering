"""Track finding resolution and reopening across completed scans."""

from alembic import op
import sqlalchemy as sa

revision = "20261114_19"
down_revision = "20261114_18"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scan_findings", sa.Column("resolved_at", sa.DateTime(), nullable=True))
    op.add_column("scan_findings", sa.Column("reopened_at", sa.DateTime(), nullable=True))
    op.create_index("idx_findings_resolved_at", "scan_findings", ["resolved_at"])


def downgrade() -> None:
    op.drop_index("idx_findings_resolved_at", table_name="scan_findings")
    op.drop_column("scan_findings", "reopened_at")
    op.drop_column("scan_findings", "resolved_at")
