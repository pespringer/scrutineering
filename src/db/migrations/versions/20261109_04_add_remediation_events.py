"""Persist remediation lifecycle events."""
from alembic import op
import sqlalchemy as sa

revision = "20261109_04"
down_revision = "20261109_03"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("remediation_events",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("remediation_id", sa.BigInteger(), sa.ForeignKey("remediations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=True),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
    )
    op.create_index("idx_remediation_events_remediation_id", "remediation_events", ["remediation_id"])
    op.create_index("idx_remediation_events_sequence", "remediation_events", ["remediation_id", "sequence"])

def downgrade():
    op.drop_index("idx_remediation_events_sequence", table_name="remediation_events")
    op.drop_index("idx_remediation_events_remediation_id", table_name="remediation_events")
    op.drop_table("remediation_events")
