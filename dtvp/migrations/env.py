from alembic import context

from dtvp import migration_models  # noqa: F401 — retain historical tables in schema metadata
from dtvp.models import Base

connection = context.config.attributes["connection"]
context.configure(connection=connection, target_metadata=Base.metadata, compare_type=True)
with context.begin_transaction():
    context.run_migrations()
