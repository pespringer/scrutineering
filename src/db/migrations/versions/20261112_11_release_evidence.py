"""Persist release evidence records attached to publications."""
from alembic import op
import sqlalchemy as sa

revision = "20261112_11"
down_revision = "20261112_10"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "remediation_release_evidence",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("publication_id", sa.BigInteger(), sa.ForeignKey("remediation_publications.id", ondelete="CASCADE"), nullable=False),
        sa.Column("evidence_key", sa.String(length=128), nullable=False),
        sa.Column("expected_digest", sa.String(length=71), nullable=False),
        sa.Column("observed_digest", sa.String(length=71), nullable=True),
        sa.Column("scan_status", sa.String(length=32), nullable=False),
        sa.Column("findings_before", sa.Integer(), nullable=False),
        sa.Column("findings_after", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("verification_detail", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("verified_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("publication_id", "evidence_key", name="uq_remediation_release_evidence_key"),
    )
    op.create_index("idx_remediation_release_evidence_publication_id", "remediation_release_evidence", ["publication_id"])
    op.create_index("idx_remediation_release_evidence_status", "remediation_release_evidence", ["status"])


def downgrade():
    op.drop_index("idx_remediation_release_evidence_status", table_name="remediation_release_evidence")
    op.drop_index("idx_remediation_release_evidence_publication_id", table_name="remediation_release_evidence")
    op.drop_table("remediation_release_evidence")
