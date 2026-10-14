"""Independent team review scope and coordinator-owned final scores."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade():
    document = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
    op.create_table(
        "review_scopes",
        sa.Column("finding_id", sa.String(36), sa.ForeignKey("findings.id"), primary_key=True),
        sa.Column("workspace_ids", document, nullable=False),
    )
    op.create_table(
        "final_rescorings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finding_id", sa.String(36), sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("coordinator_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("evidence_revision", sa.Integer(), nullable=False),
        sa.Column("review_digest", sa.String(64), nullable=False),
        sa.Column("proposal", document, nullable=False),
    )
    op.create_index("ix_final_rescorings_finding_id", "final_rescorings", ["finding_id"])


def downgrade():
    raise RuntimeError("Restore the pre-upgrade backup; destructive downgrades are disabled")
