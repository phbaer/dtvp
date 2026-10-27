from __future__ import annotations

import logging

from alembic import context
from sqlalchemy import create_engine, pool

from dtvp.database import Base, get_database_url
from dtvp import models as _models  # noqa: F401 - registers metadata

config = context.config
target_metadata = Base.metadata
logger = logging.getLogger("dtvp.database.migrations")


def _report_applied_migration(ctx, step, heads, run_args) -> None:
    message = f"DTVP database migration applied (revision={step.up_revision_id})"
    logger.info(message)
    print(message, flush=True)


def run_migrations_offline() -> None:
    context.configure(
        url=str(get_database_url()),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def _run_with_connection(connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        on_version_apply=[_report_applied_migration],
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connection = config.attributes.get("connection")
    if connection is not None:
        _run_with_connection(connection)
        return

    engine = create_engine(get_database_url(), poolclass=pool.NullPool)
    try:
        with engine.connect() as opened_connection:
            _run_with_connection(opened_connection)
    finally:
        engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
