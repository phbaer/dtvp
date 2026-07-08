import hashlib
import re
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


MIGRATION_FILENAME_RE = re.compile(r"^(\d+)_(.+)\.sql$")


@dataclass(frozen=True)
class SQLiteMigration:
    version: int
    name: str
    path: Path
    sql: str
    checksum: str


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _migration_checksum(sql: str) -> str:
    return hashlib.sha256(sql.encode("utf-8")).hexdigest()


def _iter_sql_statements(sql: str) -> list[str]:
    statements: list[str] = []
    pending = ""
    for line in sql.splitlines():
        if not pending and not line.strip():
            continue
        if not pending and line.lstrip().startswith("--"):
            continue
        pending = f"{pending}\n{line}" if pending else line
        if sqlite3.complete_statement(pending):
            statement = pending.strip()
            if statement:
                statements.append(statement)
            pending = ""

    if pending.strip():
        raise ValueError("Incomplete SQL statement in migration")

    return statements


def load_sqlite_migrations(migrations_path: str | Path) -> list[SQLiteMigration]:
    path = Path(migrations_path)
    if not path.exists():
        raise FileNotFoundError(f"SQLite migration path does not exist: {path}")

    migrations: list[SQLiteMigration] = []
    versions: set[int] = set()
    for migration_path in sorted(path.glob("*.sql")):
        match = MIGRATION_FILENAME_RE.match(migration_path.name)
        if not match:
            raise ValueError(
                f"Invalid SQLite migration filename: {migration_path.name}"
            )
        version = int(match.group(1))
        if version in versions:
            raise ValueError(f"Duplicate SQLite migration version: {version}")
        versions.add(version)
        sql = migration_path.read_text(encoding="utf-8")
        migrations.append(
            SQLiteMigration(
                version=version,
                name=match.group(2),
                path=migration_path,
                sql=sql,
                checksum=_migration_checksum(sql),
            )
        )

    return migrations


def _ensure_migration_table(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            namespace TEXT NOT NULL,
            version INTEGER NOT NULL,
            name TEXT NOT NULL,
            checksum TEXT NOT NULL,
            applied_at TEXT NOT NULL,
            PRIMARY KEY (namespace, version)
        )
        """
    )


def _applied_migrations(
    connection: sqlite3.Connection,
    namespace: str,
) -> dict[int, str]:
    rows = connection.execute(
        """
        SELECT version, checksum
        FROM schema_migrations
        WHERE namespace = ?
        """,
        (namespace,),
    ).fetchall()
    return {int(version): str(checksum) for version, checksum in rows}


def run_sqlite_migrations(
    connection: sqlite3.Connection,
    *,
    namespace: str,
    migrations_path: str | Path,
    logger: Any = None,
) -> list[int]:
    _ensure_migration_table(connection)
    connection.commit()
    migrations = load_sqlite_migrations(migrations_path)
    applied = _applied_migrations(connection, namespace)
    applied_now: list[int] = []

    for migration in migrations:
        existing_checksum = applied.get(migration.version)
        if existing_checksum is not None:
            if existing_checksum != migration.checksum:
                raise RuntimeError(
                    "SQLite migration checksum changed for "
                    f"{namespace} version {migration.version}: {migration.path.name}"
                )
            continue

        statements = _iter_sql_statements(migration.sql)
        with connection:
            for statement in statements:
                connection.execute(statement)
            connection.execute(
                """
                INSERT INTO schema_migrations (
                    namespace,
                    version,
                    name,
                    checksum,
                    applied_at
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    namespace,
                    migration.version,
                    migration.name,
                    migration.checksum,
                    _utc_now_iso(),
                ),
            )
        applied_now.append(migration.version)
        if logger:
            logger.info(
                "Applied SQLite migration %s/%s from %s",
                namespace,
                migration.version,
                migration.path.name,
            )

    return applied_now
