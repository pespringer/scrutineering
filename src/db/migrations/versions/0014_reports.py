"""Signed weekly and on-demand reports.

Revision ID: 0014_reports
Revises: 0013_deployments
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0014_reports"
down_revision: Union[str, None] = "0013_deployments"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

PRIMARY_KEY = sa.BigInteger().with_variant(sa.Integer(), "sqlite")


def upgrade() -> None:
    op.create_table(
        "reports",
        sa.Column("id", PRIMARY_KEY, primary_key=True, autoincrement=True),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("period_start", sa.DateTime(), nullable=False),
        sa.Column("period_end", sa.DateTime(), nullable=False),
        sa.Column("document", sa.Text(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("signature", sa.String(length=256), nullable=True),
        sa.Column("key_id", sa.String(length=80), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("kind", "period_start", "period_end", name="uq_reports_kind_period"),
    )
    op.create_index("idx_reports_period_start", "reports", ["period_start"])


def downgrade() -> None:
    op.drop_index("idx_reports_period_start", table_name="reports")
    op.drop_table("reports")
