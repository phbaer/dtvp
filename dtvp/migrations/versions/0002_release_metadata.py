"""Track optimistic versions of DTVP-owned release context."""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "releases", sa.Column("metadata_version", sa.Integer(), nullable=False, server_default="0")
    )


def downgrade():
    raise RuntimeError("Restore the pre-upgrade backup; destructive downgrades are disabled")
