"""Publish remediations as GitHub pull requests: the `published` status and the publication record.

Drops the publication columns that held client-asserted post-merge evidence (digests and finding
counts posted in callbacks) and the unused PR columns on `remediations`; the server now rescans.

Revision ID: 0007_remediation_publication
Revises: 0006_remediation_candidate
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0007_remediation_publication"
down_revision: Union[str, None] = "0006_remediation_candidate"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

BEFORE = ("proposed", "approved", "building", "verifying", "needs_acceptance", "ready", "completed", "failed",
          "cancelled")
AFTER = ("proposed", "approved", "building", "verifying", "needs_acceptance", "ready", "published", "completed",
         "failed", "cancelled")
REMEDIATION_COLUMNS = (
    ("pr_url", sa.String(length=2048)),
    ("pr_number", sa.Integer()),
    ("branch_name", sa.String(length=512)),
)
ADDED = (
    ("branch", sa.String(length=256)),
    ("base_branch", sa.String(length=256)),
    ("head_commit", sa.String(length=64)),
    ("image_digest", sa.String(length=128)),
)
DROPPED = (
    ("observed_digest", sa.String(length=71), None),
    ("verification_status", sa.String(length=32), None),
    ("verification_detail", sa.JSON(), "'{}'"),
    ("scan_status", sa.String(length=32), None),
    ("post_merge_scan_id", sa.String(length=64), None),
    ("findings_before", sa.Integer(), None),
    ("findings_after", sa.Integer(), None),
    ("rollback_command", sa.JSON(), "'[]'"),
)


def _set_statuses(values: tuple[str, ...], mapping: dict[str, str]) -> None:
    case = " ".join(f"WHEN '{old}' THEN '{new}'" for old, new in mapping.items())
    update = f"UPDATE remediations SET status = CASE status {case} ELSE status END" if mapping else None
    if op.get_bind().dialect.name == "postgresql":
        op.execute("ALTER TABLE remediations ALTER COLUMN status TYPE varchar(32) USING status::text")
        op.execute("DROP TYPE remediationstatus")
        if update:
            op.execute(update)
        sa.Enum(*values, name="remediationstatus").create(op.get_bind())
        op.execute(
            "ALTER TABLE remediations ALTER COLUMN status TYPE remediationstatus USING status::remediationstatus"
        )
        return
    with op.batch_alter_table("remediations") as batch:
        batch.alter_column("status", type_=sa.String(32), existing_nullable=False)
    if update:
        op.execute(update)
    with op.batch_alter_table("remediations") as batch:
        batch.alter_column("status", type_=sa.Enum(*values, name="remediationstatus"), existing_nullable=False)


def upgrade() -> None:
    _set_statuses(AFTER, {})
    with op.batch_alter_table("remediations") as batch:
        for name, _ in REMEDIATION_COLUMNS:
            batch.drop_column(name)
    with op.batch_alter_table("remediation_publications") as batch:
        for name, _, _ in DROPPED:
            batch.drop_column(name)
        for name, type_ in ADDED:
            batch.add_column(sa.Column(name, type_, nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("remediation_publications") as batch:
        for name, _ in reversed(ADDED):
            batch.drop_column(name)
        for name, type_, default in DROPPED:
            server_default = sa.text(default) if default else None
            batch.add_column(sa.Column(name, type_, nullable=default is None, server_default=server_default))
    with op.batch_alter_table("remediations") as batch:
        for name, type_ in REMEDIATION_COLUMNS:
            batch.add_column(sa.Column(name, type_, nullable=True))
    # A published remediation had a verified candidate: before this revision that is `ready`.
    _set_statuses(BEFORE, {"published": "ready"})
