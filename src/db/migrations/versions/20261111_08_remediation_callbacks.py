"""Persist provider callbacks and post-merge verification results."""
from alembic import op
import sqlalchemy as sa

revision = "20261111_08"
down_revision = "20261111_07"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("remediation_publications", sa.Column("merged_at", sa.DateTime(), nullable=True))
    op.add_column("remediation_publications", sa.Column("merge_commit", sa.String(length=64), nullable=True))
    op.add_column("remediation_publications", sa.Column("observed_digest", sa.String(length=71), nullable=True))
    op.add_column("remediation_publications", sa.Column("verification_status", sa.String(length=32), nullable=True))
    op.add_column("remediation_publications", sa.Column("verification_detail", sa.JSON(), nullable=False, server_default="{}"))
    op.create_table(
        "remediation_webhook_events",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("remediation_id", sa.BigInteger(), sa.ForeignKey("remediations.id", ondelete="SET NULL"), nullable=True),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("event_id", sa.String(length=256), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("received_at", sa.DateTime(), server_default=sa.func.now()),
        sa.UniqueConstraint("provider", "event_id", name="uq_remediation_webhook_event"),
    )
    op.create_index("idx_remediation_webhook_events_remediation_id", "remediation_webhook_events", ["remediation_id"])


def downgrade():
    op.drop_index("idx_remediation_webhook_events_remediation_id", table_name="remediation_webhook_events")
    op.drop_table("remediation_webhook_events")
    for column in ("verification_detail", "verification_status", "observed_digest", "merge_commit", "merged_at"):
        op.drop_column("remediation_publications", column)
