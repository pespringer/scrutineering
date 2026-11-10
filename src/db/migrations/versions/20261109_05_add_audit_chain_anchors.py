"""Persist external audit-chain anchor receipts."""
from alembic import op
import sqlalchemy as sa

revision = "20261109_05"
down_revision = "20261109_04"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "audit_chain_anchors",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("anchor_id", sa.String(length=256), nullable=False),
        sa.Column("head_hash", sa.String(length=71), nullable=False),
        sa.Column("record_id", sa.String(length=128), nullable=False),
        sa.Column("anchored_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("anchor_id", name="uq_audit_chain_anchors_anchor_id"),
    )
    op.create_index("idx_audit_chain_anchors_head_hash", "audit_chain_anchors", ["head_hash"])


def downgrade():
    op.drop_index("idx_audit_chain_anchors_head_hash", table_name="audit_chain_anchors")
    op.drop_table("audit_chain_anchors")
