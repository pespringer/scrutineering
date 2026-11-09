"""Add tamper-evident audit chain columns.

Revision ID: 20261109_02
Revises: 20261108_01
"""

from alembic import op
import sqlalchemy as sa

revision = "20261109_02"
down_revision = "20261108_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("audit_log", sa.Column("previous_hash", sa.String(length=64), nullable=True))
    op.add_column("audit_log", sa.Column("record_hash", sa.String(length=64), nullable=True))
    op.create_index("ix_audit_log_record_hash", "audit_log", ["record_hash"])


def downgrade() -> None:
    op.drop_index("ix_audit_log_record_hash", table_name="audit_log")
    op.drop_column("audit_log", "record_hash")
    op.drop_column("audit_log", "previous_hash")
