"""Replace the remediation statuses with the single Phase 4 lifecycle.

Revision ID: 0005_remediation_lifecycle
Revises: 0004_os_package_upgrade_action
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0005_remediation_lifecycle"
down_revision: Union[str, None] = "0004_os_package_upgrade_action"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

OLD = ("pending", "analyzing", "patching", "building", "verifying", "pr_opened", "completed", "failed", "skipped",
       "requires_review")
NEW = ("proposed", "approved", "building", "verifying", "needs_acceptance", "ready", "completed", "failed",
       "cancelled")
# Old status -> new status. A PR that was opened had passed validation: that is "ready".
UPGRADE = {
    "pending": "proposed", "requires_review": "proposed", "analyzing": "approved", "patching": "building",
    "building": "building", "verifying": "verifying", "pr_opened": "ready", "completed": "completed",
    "failed": "failed", "skipped": "cancelled",
}
DOWNGRADE = {
    "proposed": "requires_review", "approved": "analyzing", "building": "building", "verifying": "verifying",
    "needs_acceptance": "requires_review", "ready": "pr_opened", "completed": "completed", "failed": "failed",
    "cancelled": "skipped",
}


def _convert(source: tuple[str, ...], target: tuple[str, ...], mapping: dict[str, str]) -> None:
    case = " ".join(f"WHEN '{old}' THEN '{new}'" for old, new in mapping.items())
    if op.get_bind().dialect.name == "postgresql":
        op.execute("ALTER TABLE remediations ALTER COLUMN status TYPE varchar(32) USING status::text")
        op.execute("DROP TYPE remediationstatus")
        op.execute(f"UPDATE remediations SET status = CASE status {case} END")
        sa.Enum(*target, name="remediationstatus").create(op.get_bind())
        op.execute(
            "ALTER TABLE remediations ALTER COLUMN status TYPE remediationstatus USING status::remediationstatus"
        )
        return
    with op.batch_alter_table("remediations") as batch:
        batch.alter_column("status", type_=sa.String(32), existing_nullable=False)
    op.execute(f"UPDATE remediations SET status = CASE status {case} END")
    with op.batch_alter_table("remediations") as batch:
        batch.alter_column("status", type_=sa.Enum(*target, name="remediationstatus"), existing_nullable=False)


def upgrade() -> None:
    _convert(OLD, NEW, UPGRADE)


def downgrade() -> None:
    _convert(NEW, OLD, DOWNGRADE)
