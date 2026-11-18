"""Signatures on SBOMs, and the public keys that made them.

Revision ID: 0011_signing
Revises: 0010_sboms
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0011_signing"
down_revision: Union[str, None] = "0010_sboms"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

PRIMARY_KEY = sa.BigInteger().with_variant(sa.Integer(), "sqlite")


def upgrade() -> None:
    op.create_table(
        "signing_keys",
        sa.Column("id", PRIMARY_KEY, primary_key=True, autoincrement=True),
        sa.Column("key_id", sa.String(length=80), nullable=False),
        sa.Column("public_key_pem", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("key_id", name="uq_signing_keys_key_id"),
    )
    with op.batch_alter_table("sboms") as batch:
        batch.add_column(sa.Column("signature", sa.String(length=256), nullable=True))
        batch.add_column(sa.Column("key_id", sa.String(length=80), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("sboms") as batch:
        batch.drop_column("key_id")
        batch.drop_column("signature")
    op.drop_table("signing_keys")
