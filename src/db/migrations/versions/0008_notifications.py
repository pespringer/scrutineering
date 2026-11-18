"""Notifications outbox: one row per message per channel, written with the status change.

Revision ID: 0008_notifications
Revises: 0007_remediation_publication
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0008_notifications"
down_revision: Union[str, None] = "0007_remediation_publication"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

PRIMARY_KEY = sa.BigInteger().with_variant(sa.Integer(), "sqlite")


def upgrade() -> None:
    op.create_table(
        "notifications",
        sa.Column("id", PRIMARY_KEY, primary_key=True, autoincrement=True),
        sa.Column("channel", sa.String(length=16), nullable=False),
        sa.Column("event", sa.String(length=64), nullable=False),
        sa.Column(
            "remediation_id", sa.BigInteger(), sa.ForeignKey("remediations.id", ondelete="SET NULL"), nullable=True
        ),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("next_attempt_at", sa.DateTime(), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("sent_at", sa.DateTime(), nullable=True),
    )
    op.create_index("idx_notifications_due", "notifications", ["status", "next_attempt_at"])
    op.create_index("idx_notifications_remediation_id", "notifications", ["remediation_id"])


def downgrade() -> None:
    op.drop_index("idx_notifications_remediation_id", table_name="notifications")
    op.drop_index("idx_notifications_due", table_name="notifications")
    op.drop_table("notifications")
