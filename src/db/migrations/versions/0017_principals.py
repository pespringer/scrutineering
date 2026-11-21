"""People who signed in, for access reviews (docs/design/multi-user-roles.md).

Revision ID: 0017_principals
Revises: 0016_remediation_actors
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0017_principals"
down_revision: Union[str, None] = "0016_remediation_actors"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

PRIMARY_KEY = sa.BigInteger().with_variant(sa.Integer(), "sqlite")


def upgrade() -> None:
    op.create_table(
        "principals",
        sa.Column("id", PRIMARY_KEY, primary_key=True, autoincrement=True),
        sa.Column("subject", sa.String(length=128), nullable=False, unique=True),
        sa.Column("email", sa.String(length=320), nullable=True),
        sa.Column("roles", sa.JSON(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_principals_last_seen_at", "principals", ["last_seen_at"])


def downgrade() -> None:
    op.drop_index("ix_principals_last_seen_at", table_name="principals")
    op.drop_table("principals")
