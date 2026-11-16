"""Add an explicit blocked terminal remediation outcome."""

from alembic import op

revision = "20261114_27"
down_revision = "20261114_26"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TYPE remediationstatus ADD VALUE IF NOT EXISTS 'blocked'")


def downgrade() -> None:
    # PostgreSQL does not support removing an enum value in place. Existing
    # blocked records must be migrated before a manual type replacement.
    pass
