"""Add the os_package_upgrade remediation action type.

Revision ID: 0004_os_package_upgrade_action
Revises: 0003_image_sources
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0004_os_package_upgrade_action"
down_revision: Union[str, None] = "0003_image_sources"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


OLD = ("base_image_bump", "dependency_update", "config_change", "package_removal", "custom")
NEW = (*OLD, "os_package_upgrade")


def _alter(values: tuple[str, ...]) -> None:
    with op.batch_alter_table("remediation_actions") as batch:
        batch.alter_column("action_type", type_=sa.Enum(*values, name="remediationactiontype"), existing_nullable=False)


def upgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        with op.get_context().autocommit_block():
            op.execute("ALTER TYPE remediationactiontype ADD VALUE IF NOT EXISTS 'os_package_upgrade'")
    else:
        _alter(NEW)


def downgrade() -> None:
    # Postgres cannot drop an enum value; the unused value stays behind.
    if op.get_bind().dialect.name != "postgresql":
        _alter(OLD)
