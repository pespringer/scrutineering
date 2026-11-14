"""Track the follow-up scan associated with a merged publication."""

from alembic import op
import sqlalchemy as sa


revision = "20261114_18"
down_revision = "20261113_17"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("remediation_publications", sa.Column("post_merge_scan_id", sa.String(length=64), nullable=True))


def downgrade() -> None:
    op.drop_column("remediation_publications", "post_merge_scan_id")
