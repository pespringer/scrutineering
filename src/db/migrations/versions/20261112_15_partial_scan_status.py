"""Allow durable scans to represent partial scanner completion."""

from alembic import op

revision = "20261112_15"
down_revision = "20261112_14"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TYPE scanstatus ADD VALUE IF NOT EXISTS 'partial'")


def downgrade() -> None:
    # PostgreSQL enum values cannot be removed safely in-place; retain the
    # value and let the application stop emitting it on rollback.
    pass
