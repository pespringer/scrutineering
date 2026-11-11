"""Persist provider publication attempts and idempotency keys."""
from alembic import op
import sqlalchemy as sa

revision = "20261111_07"
down_revision = "20261110_06"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "remediation_publications",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("remediation_id", sa.BigInteger(), sa.ForeignKey("remediations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("repository", sa.String(length=256), nullable=False),
        sa.Column("idempotency_key", sa.String(length=256), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("url", sa.String(length=2048), nullable=True),
        sa.Column("provider_number", sa.Integer(), nullable=True),
        sa.Column("request_hash", sa.String(length=64), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("provider", "repository", "idempotency_key", name="uq_remediation_publication_key"),
    )
    op.create_index("idx_remediation_publications_remediation_id", "remediation_publications", ["remediation_id"])
    op.create_index("idx_remediation_publications_status", "remediation_publications", ["status"])


def downgrade():
    op.drop_index("idx_remediation_publications_status", table_name="remediation_publications")
    op.drop_index("idx_remediation_publications_remediation_id", table_name="remediation_publications")
    op.drop_table("remediation_publications")
