"""Durable instance-wide native advisory provider pacing, independent of projects."""

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "advisory_provider_throttles",
        sa.Column("provider", sa.String(20), primary_key=True),
        sa.Column("last_dispatch_at", sa.DateTime(timezone=True)),
        sa.Column("cooldown_until", sa.DateTime(timezone=True)),
    )


def downgrade():
    raise RuntimeError("Restore the pre-upgrade backup; destructive downgrades are disabled")
