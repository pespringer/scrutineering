"""Allow scanner finding titles longer than 1024 characters."""

from alembic import op
import sqlalchemy as sa

revision = "20261114_26"
down_revision = "20261114_25"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column("scan_findings", "title", existing_type=sa.String(length=1024), type_=sa.Text(), existing_nullable=False)


def downgrade() -> None:
    op.alter_column("scan_findings", "title", existing_type=sa.Text(), type_=sa.String(length=1024), existing_nullable=False)
