"""Record where each image is built from.

Revision ID: 0003_image_sources
Revises: 0002_finding_observations
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0003_image_sources"
down_revision: Union[str, None] = "0002_finding_observations"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "image_sources",
        sa.Column("id", sa.BigInteger().with_variant(sa.Integer(), "sqlite"), autoincrement=True, nullable=False),
        sa.Column("image_id", sa.BigInteger(), nullable=False),
        sa.Column("repository", sa.String(length=1024), nullable=False),
        sa.Column("ref", sa.String(length=256), nullable=False),
        sa.Column("dockerfile_path", sa.String(length=512), nullable=False),
        sa.Column("build_context", sa.String(length=512), nullable=False),
        sa.Column("build_args", sa.JSON(), nullable=False),
        sa.Column("test_command", sa.JSON(), nullable=True),
        sa.Column("updated_by", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["image_id"], ["images.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("image_id"),
    )


def downgrade() -> None:
    op.drop_table("image_sources")
