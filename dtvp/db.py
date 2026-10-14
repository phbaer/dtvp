from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

ROOT = Path(__file__).resolve().parent.parent


def engine_for(url: str):
    options = {"pool_pre_ping": True}
    if url.startswith("sqlite"):
        options.update(connect_args={"check_same_thread": False})
        if url.endswith(":memory:"):
            options["poolclass"] = StaticPool
    engine = create_engine(url, **options)
    if url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def foreign_keys(connection, _):
            connection.execute("PRAGMA foreign_keys=ON")

    return engine


def migrate(engine, backup_dir=None):
    config = Config(str(ROOT / "alembic.ini"))
    with engine.connect() as connection:
        postgres = engine.dialect.name == "postgresql"
        if postgres:
            connection.execute(text("SET statement_timeout = '60s'"))
            connection.execute(text("SELECT pg_advisory_lock(684227093)"))
            connection.execute(text("SET statement_timeout = '0'"))
            connection.commit()
        try:
            current = MigrationContext.configure(connection).get_current_revision()
            head = ScriptDirectory.from_config(config).get_current_head()
            if current and current != head:
                from dtvp.backup import backup

                backup(connection, backup_dir or ROOT / "data" / "migration-backups", current)
                connection.commit()
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
            connection.commit()
        finally:
            if postgres:
                connection.rollback()
                connection.execute(text("SELECT pg_advisory_unlock(684227093)"))
                connection.commit()


def schema_ready(engine):
    config = Config(str(ROOT / "alembic.ini"))
    with engine.connect() as connection:
        return MigrationContext.configure(connection).get_current_revision() == (
            ScriptDirectory.from_config(config).get_current_head()
        )


def sessions(engine):
    return sessionmaker(engine, expire_on_commit=False)
