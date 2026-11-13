"""Store scanner-provided repository source coordinates."""

from alembic import op
import sqlalchemy as sa

revision = "20261113_17"
down_revision = "20261113_16"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scan_findings", sa.Column("file_path", sa.String(length=1024), nullable=True))


def downgrade() -> None:
    op.drop_column("scan_findings", "file_path")
