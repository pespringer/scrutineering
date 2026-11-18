"""Runtime discovery records when an image was last seen running.

Revision ID: 0009_image_last_seen_running
Revises: 0008_notifications
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0009_image_last_seen_running"
down_revision: Union[str, None] = "0008_notifications"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("images", sa.Column("last_seen_running_at", sa.DateTime(), nullable=True))
    op.create_index("idx_images_last_seen_running_at", "images", ["last_seen_running_at"])


def downgrade() -> None:
    op.drop_index("idx_images_last_seen_running_at", table_name="images")
    with op.batch_alter_table("images") as batch:
        batch.drop_column("last_seen_running_at")
