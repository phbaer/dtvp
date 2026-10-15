"""Disposable knowledge-state projections; authoritative data lives in the journal."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade():
    document = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
    op.create_table(
        "knowledge_heads",
        sa.Column("ref_key", sa.String(1000), primary_key=True),
        sa.Column("project_id", sa.String(200), nullable=False),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("state_sha", sa.String(64), nullable=False),
    )
    op.create_index("ix_knowledge_heads_project_id", "knowledge_heads", ["project_id"])
    op.create_table(
        "knowledge_records",
        sa.Column("ref_key", sa.String(1000), primary_key=True),
        sa.Column("section", sa.String(40), primary_key=True),
        sa.Column("record_key", sa.String(200), primary_key=True),
        sa.Column("sha", sa.String(64), nullable=False),
        sa.Column("data", document, nullable=False),
    )
    op.create_table(
        "knowledge_cursor",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("publication_sha", sa.String(64)),
        sa.Column("sequence", sa.Integer(), nullable=False),
    )
    op.execute("INSERT INTO knowledge_cursor (id, sequence) VALUES (1, 0)")


def downgrade():
    raise RuntimeError("Restore the pre-upgrade backup; destructive downgrades are disabled")
