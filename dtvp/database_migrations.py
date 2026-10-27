"""Serialized, observable Alembic upgrades for the DTVP database."""

from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, text
from sqlalchemy.engine import make_url

from .database import get_database_url, get_engine

logger = logging.getLogger(__name__)
_POSTGRES_MIGRATION_LOCK = 0x44545650


def _announce(message: str) -> None:
    logger.info(message)
    print(message, flush=True)


@contextmanager
def _sqlite_migration_lock(engine: Engine) -> Iterator[None]:
    # SQLite is the default for local development. Lock a sidecar file so two
    # local app processes do not race to create/upgrade the same database.
    import fcntl

    database_path = engine.url.database
    if not database_path or database_path == ":memory:":
        yield
        return
    path = Path(database_path)
    lock_path = path.resolve().with_suffix(path.suffix + ".migration.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _alembic_config(connection) -> Config:
    config_path = Path(__file__).resolve().parent.parent / "alembic.ini"
    config = Config(str(config_path))
    config.attributes["connection"] = connection
    return config


def run_database_migrations() -> str:
    """Upgrade to Alembic head, serialize runners, and return applied revision."""
    engine = get_engine()
    url = get_database_url()
    dialect = make_url(str(url)).get_backend_name()
    _announce(f"DTVP database migration check started (dialect={dialect})")

    with engine.connect() as connection:
        if dialect == "postgresql":
            connection.execute(
                text("SELECT pg_advisory_lock(:key)"),
                {"key": _POSTGRES_MIGRATION_LOCK},
            )
            connection.commit()
            try:
                command.upgrade(_alembic_config(connection), "head")
            finally:
                connection.execute(
                    text("SELECT pg_advisory_unlock(:key)"),
                    {"key": _POSTGRES_MIGRATION_LOCK},
                )
                connection.commit()
        else:
            with _sqlite_migration_lock(engine):
                command.upgrade(_alembic_config(connection), "head")

        from alembic.runtime.migration import MigrationContext

        revisions = MigrationContext.configure(connection).get_current_heads()

    revision = ",".join(revisions) if revisions else "base"
    _announce(f"DTVP database schema is current (revision={revision})")
    return revision


def main() -> None:
    logging.basicConfig(level=os.getenv("DTVP_LOG_LEVEL", "INFO"))
    run_database_migrations()


__all__ = ["run_database_migrations", "main"]
