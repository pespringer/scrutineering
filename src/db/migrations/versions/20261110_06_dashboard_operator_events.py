"""Add audit event type for operator scan cancellation."""

from alembic import op

revision = "20261110_06"
down_revision = "20261109_05"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TYPE auditeventtype ADD VALUE IF NOT EXISTS 'scan_cancelled'")


def downgrade() -> None:
    # PostgreSQL does not safely remove enum values; retain the additive value.
    pass
