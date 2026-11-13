"""Add durable archive and finding workflow state for dashboard bulk actions."""

from alembic import op
import sqlalchemy as sa

revision = "20261113_16"
down_revision = "20261112_15"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("archived", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("scan_findings", sa.Column("acknowledged", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("scan_findings", sa.Column("assigned_to", sa.String(length=128), nullable=True))


def downgrade() -> None:
    op.drop_column("scan_findings", "assigned_to")
    op.drop_column("scan_findings", "acknowledged")
    op.drop_column("scans", "archived")
