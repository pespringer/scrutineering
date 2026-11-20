"""Running containers of tracked images, recorded by runtime discovery.

Revision ID: 0013_deployments
Revises: 0012_evidence_bundles
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0013_deployments"
down_revision: Union[str, None] = "0012_evidence_bundles"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

PRIMARY_KEY = sa.BigInteger().with_variant(sa.Integer(), "sqlite")


def upgrade() -> None:
    op.create_table(
        "deployments",
        sa.Column("id", PRIMARY_KEY, primary_key=True, autoincrement=True),
        sa.Column("container_id", sa.String(length=128), nullable=False),
        sa.Column("name", sa.String(length=256), nullable=False),
        sa.Column("image_ref", sa.String(length=1024), nullable=False),
        sa.Column("image_id", sa.BigInteger(), sa.ForeignKey("images.id", ondelete="CASCADE"), nullable=False),
        sa.Column("running_digests", sa.JSON(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False),
        sa.Column("gone_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("container_id", name="uq_deployments_container_id"),
    )
    op.create_index("idx_deployments_image_id", "deployments", ["image_id"])
    op.create_index("idx_deployments_gone_at", "deployments", ["gone_at"])


def downgrade() -> None:
    op.drop_index("idx_deployments_gone_at", table_name="deployments")
    op.drop_index("idx_deployments_image_id", table_name="deployments")
    op.drop_table("deployments")
