"""Persist normalized post-merge evidence and rollback output."""
from alembic import op
import sqlalchemy as sa

revision = "20261111_09"
down_revision = "20261111_08"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("remediation_publications", sa.Column("scan_status", sa.String(length=32), nullable=True))
    op.add_column("remediation_publications", sa.Column("findings_before", sa.Integer(), nullable=True))
    op.add_column("remediation_publications", sa.Column("findings_after", sa.Integer(), nullable=True))
    op.add_column("remediation_publications", sa.Column("rollback_command", sa.JSON(), nullable=False, server_default="[]"))


def downgrade():
    for column in ("rollback_command", "findings_after", "findings_before", "scan_status"):
        op.drop_column("remediation_publications", column)
