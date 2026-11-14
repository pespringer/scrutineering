"""Add auditable, expiring finding suppressions."""

from alembic import op
import sqlalchemy as sa

revision = "20261114_20"
down_revision = "20261114_19"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "finding_suppressions",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("finding_id", sa.BigInteger(), nullable=False),
        sa.Column("reason", sa.String(length=2000), nullable=False),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["finding_id"], ["scan_findings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_finding_suppressions_finding_id", "finding_suppressions", ["finding_id"])
    op.create_index("idx_finding_suppressions_expires_at", "finding_suppressions", ["expires_at"])


def downgrade() -> None:
    op.drop_index("idx_finding_suppressions_expires_at", table_name="finding_suppressions")
    op.drop_index("idx_finding_suppressions_finding_id", table_name="finding_suppressions")
    op.drop_table("finding_suppressions")
