"""Add alert delivery queue and recovery leases."""
from alembic import op
import sqlalchemy as sa

revision = "20261112_14"
down_revision = "20261112_13"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("remediation_recovery_requests")}
    if "lease_owner" not in columns:
        op.add_column("remediation_recovery_requests", sa.Column("lease_owner", sa.String(length=128), nullable=True))
    if "lease_until" not in columns:
        op.add_column("remediation_recovery_requests", sa.Column("lease_until", sa.DateTime(), nullable=True))
    if "remediation_alert_deliveries" not in inspector.get_table_names():
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
    indexes = {index["name"] for index in sa.inspect(bind).get_indexes("remediation_alert_deliveries")}
    if "idx_remediation_alert_deliveries_status" not in indexes:
        op.create_index("idx_remediation_alert_deliveries_status", "remediation_alert_deliveries", ["status"])
    if "idx_remediation_alert_deliveries_next_attempt_at" not in indexes:
        op.create_index("idx_remediation_alert_deliveries_next_attempt_at", "remediation_alert_deliveries", ["next_attempt_at"])


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "remediation_alert_deliveries" in inspector.get_table_names():
        indexes = {index["name"] for index in inspector.get_indexes("remediation_alert_deliveries")}
        if "idx_remediation_alert_deliveries_next_attempt_at" in indexes:
            op.drop_index("idx_remediation_alert_deliveries_next_attempt_at", table_name="remediation_alert_deliveries")
        if "idx_remediation_alert_deliveries_status" in indexes:
            op.drop_index("idx_remediation_alert_deliveries_status", table_name="remediation_alert_deliveries")
        op.drop_table("remediation_alert_deliveries")
    columns = {column["name"] for column in inspector.get_columns("remediation_recovery_requests")}
    if "lease_until" in columns:
        op.drop_column("remediation_recovery_requests", "lease_until")
    if "lease_owner" in columns:
        op.drop_column("remediation_recovery_requests", "lease_owner")
