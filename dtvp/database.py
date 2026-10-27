"""DTVP-owned relational database configuration and session primitives."""

from __future__ import annotations

import os
from functools import lru_cache

from sqlalchemy import create_engine, event
from sqlalchemy.engine import URL, Engine, make_url
from sqlalchemy.orm import DeclarativeBase, sessionmaker


class Base(DeclarativeBase):
    """Base for DTVP-owned relational models."""


def get_database_url() -> str | URL:
    """Build the configured SQLAlchemy URL without interpolating credentials."""
    explicit_url = os.getenv("DTVP_DATABASE_URL", "").strip()
    if explicit_url:
        url = make_url(explicit_url)
        if url.drivername == "postgresql":
            url = url.set(drivername="postgresql+psycopg")
        return url

    host = os.getenv("DTVP_DB_HOST", "").strip()
    if host:
        return URL.create(
            "postgresql+psycopg",
            username=os.getenv("DTVP_DB_USER", "dtvp"),
            password=os.getenv("DTVP_DB_PASSWORD", ""),
            host=host,
            port=int(os.getenv("DTVP_DB_PORT", "5432")),
            database=os.getenv("DTVP_DB_NAME", "dtvp"),
        )

    # File-backed storage keeps a fresh local checkout easy to run. Compose
    # configures the separate PostgreSQL service explicitly.
    return os.getenv("DTVP_LOCAL_DATABASE_URL", "sqlite:///data/dtvp.sqlite3")


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    url = get_database_url()
    connect_args = {"check_same_thread": False} if str(url).startswith("sqlite") else {}
    engine = create_engine(url, pool_pre_ping=True, connect_args=connect_args)
    if engine.dialect.name == "sqlite":
        @event.listens_for(engine, "connect")
        def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine


@lru_cache(maxsize=1)
def get_session_factory() -> sessionmaker:
    return sessionmaker(bind=get_engine(), expire_on_commit=False)
