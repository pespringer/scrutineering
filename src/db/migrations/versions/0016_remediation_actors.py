"""Who proposed, executed, accepted and published each remediation (docs/design/multi-user-roles.md).

Revision ID: 0016_remediation_actors
Revises: 0015_compliance_exports
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0016_remediation_actors"
down_revision: Union[str, None] = "0015_compliance_exports"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

ACTORS = ("proposed_by", "executed_by", "accepted_by", "published_by")


def upgrade() -> None:
    with op.batch_alter_table("remediations") as batch:
        for column in ACTORS:
            batch.add_column(sa.Column(column, sa.String(length=128), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("remediations") as batch:
        for column in reversed(ACTORS):
            batch.drop_column(column)
