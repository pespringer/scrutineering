"""Persist alert delivery evidence for release records."""
from alembic import op
import sqlalchemy as sa

revision = "20261112_13"
down_revision = "20261112_12"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "remediation_alert_evidence",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("publication_id", sa.BigInteger(), sa.ForeignKey("remediation_publications.id", ondelete="CASCADE"), nullable=False),
        sa.Column("delivery_key", sa.String(length=128), nullable=False),
        sa.Column("receiver", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("response_code", sa.Integer(), nullable=True),
        sa.Column("attempt", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("detail", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        sa.UniqueConstraint("publication_id", "delivery_key", name="uq_remediation_alert_evidence_key"),
    )
    op.create_index("idx_remediation_alert_evidence_publication_id", "remediation_alert_evidence", ["publication_id"])
    op.create_index("idx_remediation_alert_evidence_status", "remediation_alert_evidence", ["status"])


def downgrade():
    op.drop_index("idx_remediation_alert_evidence_status", table_name="remediation_alert_evidence")
    op.drop_index("idx_remediation_alert_evidence_publication_id", table_name="remediation_alert_evidence")
    op.drop_table("remediation_alert_evidence")
