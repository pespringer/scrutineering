"""Frozen, signed evidence for remediations that ended completed or failed.

Revision ID: 0012_evidence_bundles
Revises: 0011_signing
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0012_evidence_bundles"
down_revision: Union[str, None] = "0011_signing"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

PRIMARY_KEY = sa.BigInteger().with_variant(sa.Integer(), "sqlite")


def upgrade() -> None:
    op.create_table(
        "evidence_bundles",
        sa.Column("id", PRIMARY_KEY, primary_key=True, autoincrement=True),
        sa.Column(
            "remediation_id",
            sa.BigInteger(),
            sa.ForeignKey("remediations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("ended_at", sa.DateTime(), nullable=False),
        sa.Column("before_scan_id", sa.String(length=64), nullable=True),
        sa.Column("after_scan_id", sa.String(length=64), nullable=True),
        sa.Column("document", sa.Text(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("signature", sa.String(length=256), nullable=True),
        sa.Column("key_id", sa.String(length=80), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("idx_evidence_bundles_remediation_id", "evidence_bundles", ["remediation_id"])


def downgrade() -> None:
    op.drop_index("idx_evidence_bundles_remediation_id", table_name="evidence_bundles")
    op.drop_table("evidence_bundles")
