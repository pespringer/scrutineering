"""Add retry state to durable provider recovery requests."""
from alembic import op
import sqlalchemy as sa

revision = "20261112_12"
down_revision = "20261112_11"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("remediation_recovery_requests", sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("remediation_recovery_requests", sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="5"))
    op.add_column("remediation_recovery_requests", sa.Column("next_attempt_at", sa.DateTime(), nullable=True))


def downgrade():
    op.drop_column("remediation_recovery_requests", "next_attempt_at")
    op.drop_column("remediation_recovery_requests", "max_attempts")
    op.drop_column("remediation_recovery_requests", "attempts")
