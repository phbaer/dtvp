"""Owned CVSS policy and evidence revision bindings for explicit adoption."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("evidence", sa.Column("input_revision", sa.Integer(), nullable=True))
    op.add_column("evidence", sa.Column("published_revision", sa.Integer(), nullable=True))
    op.create_table(
        "rescore_policies",
        sa.Column("project_id", sa.String(36), sa.ForeignKey("projects.id"), primary_key=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column(
            "config", sa.JSON().with_variant(postgresql.JSONB(), "postgresql"), nullable=False
        ),
    )


def downgrade():
    raise RuntimeError("Restore the pre-upgrade backup; destructive downgrades are disabled")
