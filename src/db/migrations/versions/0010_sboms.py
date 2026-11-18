"""CycloneDX SBOMs, one per completed or partial image scan.

Revision ID: 0010_sboms
Revises: 0009_image_last_seen_running
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0010_sboms"
down_revision: Union[str, None] = "0009_image_last_seen_running"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

PRIMARY_KEY = sa.BigInteger().with_variant(sa.Integer(), "sqlite")


def upgrade() -> None:
    op.create_table(
        "sboms",
        sa.Column("id", PRIMARY_KEY, primary_key=True, autoincrement=True),
        sa.Column(
            "scan_id", sa.String(length=64), sa.ForeignKey("scans.scan_id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("image_id", sa.BigInteger(), sa.ForeignKey("images.id", ondelete="CASCADE"), nullable=False),
        sa.Column("format", sa.String(length=32), nullable=False),
        sa.Column("spec_version", sa.String(length=16), nullable=True),
        sa.Column("components", sa.Integer(), nullable=False),
        sa.Column("document", sa.Text(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("scan_id", name="uq_sboms_scan_id"),
    )
    op.create_index("idx_sboms_image_id", "sboms", ["image_id"])


def downgrade() -> None:
    op.drop_index("idx_sboms_image_id", table_name="sboms")
    op.drop_table("sboms")
