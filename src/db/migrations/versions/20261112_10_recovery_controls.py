"""Add durable publication recovery and reconciliation run records."""
from alembic import op
import sqlalchemy as sa

revision = "20261112_10"
down_revision = "20261111_09"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "remediation_recovery_requests",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("publication_id", sa.BigInteger(), sa.ForeignKey("remediation_publications.id", ondelete="CASCADE"), nullable=False),
        sa.Column("action", sa.String(length=32), nullable=False),
        sa.Column("idempotency_key", sa.String(length=256), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="requested"),
        sa.Column("note", sa.Text(), nullable=False, server_default=""),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("requested_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("acknowledged_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("publication_id", "idempotency_key", name="uq_remediation_recovery_request_key"),
    )
    op.create_index("idx_remediation_recovery_requests_publication_id", "remediation_recovery_requests", ["publication_id"])
    op.create_index("idx_remediation_recovery_requests_status", "remediation_recovery_requests", ["status"])
    op.create_table(
        "remediation_reconciliation_runs",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("discovered", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("events_recorded", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
    )
    op.create_index("idx_remediation_reconciliation_runs_started_at", "remediation_reconciliation_runs", ["started_at"])


def downgrade():
    op.drop_index("idx_remediation_reconciliation_runs_started_at", table_name="remediation_reconciliation_runs")
    op.drop_table("remediation_reconciliation_runs")
    op.drop_index("idx_remediation_recovery_requests_status", table_name="remediation_recovery_requests")
    op.drop_index("idx_remediation_recovery_requests_publication_id", table_name="remediation_recovery_requests")
    op.drop_table("remediation_recovery_requests")
