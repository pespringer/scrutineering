"""Persist remediation approval provenance."""

from alembic import op
import sqlalchemy as sa

revision = "20261109_03"
down_revision = "20261109_02"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("remediations", sa.Column("approval_token_hash", sa.String(length=64), nullable=True))
    op.add_column("remediations", sa.Column("approved_by", sa.String(length=128), nullable=True))
    op.add_column("remediations", sa.Column("approved_at", sa.DateTime(), nullable=True))
    op.create_index("idx_remediations_approved_by", "remediations", ["approved_by"])


def downgrade():
    op.drop_index("idx_remediations_approved_by", table_name="remediations")
    op.drop_column("remediations", "approved_at")
    op.drop_column("remediations", "approved_by")
    op.drop_column("remediations", "approval_token_hash")
