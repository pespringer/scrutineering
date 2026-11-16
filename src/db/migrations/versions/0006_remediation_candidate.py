"""Record what remediation execution produced: patch, candidate image, verification.

Revision ID: 0006_remediation_candidate
Revises: 0005_remediation_lifecycle
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0006_remediation_candidate"
down_revision: Union[str, None] = "0005_remediation_lifecycle"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

COLUMNS = (
    ("source_commit", sa.String(length=64)),
    ("patch", sa.Text()),
    ("candidate_image", sa.String(length=1024)),
    ("candidate_digest", sa.String(length=80)),
    ("verification", sa.JSON()),
)


def upgrade() -> None:
    with op.batch_alter_table("remediations") as batch:
        for name, type_ in COLUMNS:
            batch.add_column(sa.Column(name, type_, nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("remediations") as batch:
        for name, _ in reversed(COLUMNS):
            batch.drop_column(name)
