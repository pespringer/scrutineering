"""Persist secret-free registry source configuration and checks."""

from alembic import op
import sqlalchemy as sa


revision = "20261114_24"
down_revision = "20261114_23"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "registry_sources",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("display_name", sa.String(length=128), nullable=False),
        sa.Column("registry_host", sa.String(length=255), nullable=False),
        sa.Column("auth_mode", sa.String(length=32), nullable=False, server_default="environment"),
        sa.Column("credential_keys", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="unverified"),
        sa.Column("last_checked_at", sa.DateTime(), nullable=True),
        sa.Column("last_reference", sa.String(length=512), nullable=True),
        sa.Column("last_digest", sa.String(length=71), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("created_by", sa.String(length=128), nullable=False, server_default="operator"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("registry_host", "display_name", name="uq_registry_source_name"),
    )
    op.create_index("idx_registry_sources_enabled", "registry_sources", ["enabled"])
    op.create_index("idx_registry_sources_status", "registry_sources", ["status"])


def downgrade() -> None:
    op.drop_index("idx_registry_sources_status", table_name="registry_sources")
    op.drop_index("idx_registry_sources_enabled", table_name="registry_sources")
    op.drop_table("registry_sources")
