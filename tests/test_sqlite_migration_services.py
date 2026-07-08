import sqlite3

import pytest

from dtvp.sqlite_migration_services import (
    load_sqlite_migrations,
    run_sqlite_migrations,
)


def test_run_sqlite_migrations_applies_pending_files_once(tmp_path):
    migrations_path = tmp_path / "migrations"
    migrations_path.mkdir()
    (migrations_path / "0001_initial.sql").write_text(
        """
        CREATE TABLE example_items (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL
        );
        """,
        encoding="utf-8",
    )
    (migrations_path / "0002_add_index.sql").write_text(
        """
        CREATE INDEX idx_example_items_name
        ON example_items (name);
        """,
        encoding="utf-8",
    )
    connection = sqlite3.connect(tmp_path / "example.sqlite")
    try:
        first = run_sqlite_migrations(
            connection,
            namespace="example",
            migrations_path=migrations_path,
        )
        second = run_sqlite_migrations(
            connection,
            namespace="example",
            migrations_path=migrations_path,
        )

        assert first == [1, 2]
        assert second == []
        assert connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'example_items'"
        ).fetchone()
        rows = connection.execute(
            """
            SELECT namespace, version, name
            FROM schema_migrations
            ORDER BY version
            """
        ).fetchall()
        assert rows == [
            ("example", 1, "initial"),
            ("example", 2, "add_index"),
        ]
    finally:
        connection.close()


def test_run_sqlite_migrations_rejects_changed_applied_file(tmp_path):
    migrations_path = tmp_path / "migrations"
    migrations_path.mkdir()
    migration_path = migrations_path / "0001_initial.sql"
    migration_path.write_text(
        "CREATE TABLE example_items (id TEXT PRIMARY KEY);",
        encoding="utf-8",
    )
    connection = sqlite3.connect(tmp_path / "example.sqlite")
    try:
        assert run_sqlite_migrations(
            connection,
            namespace="example",
            migrations_path=migrations_path,
        ) == [1]

        migration_path.write_text(
            "CREATE TABLE example_items (id TEXT PRIMARY KEY, name TEXT);",
            encoding="utf-8",
        )

        with pytest.raises(RuntimeError, match="checksum changed"):
            run_sqlite_migrations(
                connection,
                namespace="example",
                migrations_path=migrations_path,
            )
    finally:
        connection.close()


def test_load_sqlite_migrations_rejects_unversioned_sql_file(tmp_path):
    migrations_path = tmp_path / "migrations"
    migrations_path.mkdir()
    (migrations_path / "initial.sql").write_text(
        "CREATE TABLE example_items (id TEXT PRIMARY KEY);",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Invalid SQLite migration filename"):
        load_sqlite_migrations(migrations_path)
