"""Add alert delivery queue and recovery leases."""
from alembic import op
import sqlalchemy as sa

revision = "20261112_14"
down_revision = "20261112_13"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("remediation_recovery_requests", sa.Column("lease_owner", sa.String(length=128), nullable=True))
    op.add_column("remediation_recovery_requests", sa.Column("lease_until", sa.DateTime(), nullable=True))
    op.create_table(
        "remediation_alert_deliveries",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("publication_id", sa.BigInteger(), sa.ForeignKey("remediation_publications.id", ondelete="CASCADE"), nullable=False),
        sa.Column("delivery_key", sa.String(length=128), nullable=False),
        sa.Column("receiver", sa.String(length=128), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="5"),
        sa.Column("next_attempt_at", sa.DateTime(), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        sa.UniqueConstraint("publication_id", "delivery_key", name="uq_remediation_alert_delivery_key"),
    )
    op.create_index("idx_remediation_alert_deliveries_status", "remediation_alert_deliveries", ["status"])
    op.create_index("idx_remediation_alert_deliveries_next_attempt_at", "remediation_alert_deliveries", ["next_attempt_at"])


def downgrade():
    op.drop_index("idx_remediation_alert_deliveries_next_attempt_at", table_name="remediation_alert_deliveries")
    op.drop_index("idx_remediation_alert_deliveries_status", table_name="remediation_alert_deliveries")
    op.drop_table("remediation_alert_deliveries")
    op.drop_column("remediation_recovery_requests", "lease_until")
    op.drop_column("remediation_recovery_requests", "lease_owner")
