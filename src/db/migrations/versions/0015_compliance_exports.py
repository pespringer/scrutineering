"""Compliance exports: requested zips with a signed manifest, kept 24 hours.

Revision ID: 0015_compliance_exports
Revises: 0014_reports
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0015_compliance_exports"
down_revision: Union[str, None] = "0014_reports"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

PRIMARY_KEY = sa.BigInteger().with_variant(sa.Integer(), "sqlite")


def upgrade() -> None:
    op.create_table(
        "compliance_exports",
        sa.Column("id", PRIMARY_KEY, primary_key=True, autoincrement=True),
        sa.Column("requested_by", sa.String(length=256), nullable=True),
        sa.Column("since", sa.DateTime(), nullable=False),
        sa.Column("until", sa.DateTime(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("files", sa.Integer(), nullable=True),
        sa.Column("size", sa.BigInteger(), nullable=True),
        sa.Column("sha256", sa.String(length=64), nullable=True),
        sa.Column("data", sa.LargeBinary(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
    )
    op.create_index("idx_compliance_exports_status", "compliance_exports", ["status"])


def downgrade() -> None:
    op.drop_index("idx_compliance_exports_status", table_name="compliance_exports")
    op.drop_table("compliance_exports")
