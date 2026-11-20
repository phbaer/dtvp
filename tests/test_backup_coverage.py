"""Every table and column of the databases is either in the dump or listed
as left out with a reason; every data-changing migration has a record
effect."""

import re
import sqlite3
from contextlib import closing

import pytest

from dtvp.backup import entities, migration_effects, upcasters
from dtvp.backup.entities import COLUMN_MAP, MIGRATION_PATHS, TABLE_MAP
from dtvp.sqlite_migration_services import load_sqlite_migrations, run_sqlite_migrations


@pytest.fixture
def migrated(tmp_path):
    """Fully migrated databases of every namespace, as the backend builds them."""
    path = tmp_path / "all.sqlite3"
    with closing(sqlite3.connect(path)) as connection:
        for namespace, migrations_path in MIGRATION_PATHS.items():
            run_sqlite_migrations(
                connection, namespace=namespace, migrations_path=migrations_path()
            )
        # AUTOINCREMENT tables create sqlite_sequence on first insert.
        connection.execute(
            "INSERT INTO access_token_audit (occurred_at, username, token_id, agent, "
            "action, outcome, target_json, detail) VALUES ('t', 'u', 'i', 'a', 'x', 'o', '{}', '')"
        )
        connection.commit()
        tables = {
            row[0]: [column[1] for column in connection.execute(f"PRAGMA table_info({row[0]})")]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
    return tables


def test_every_table_and_column_is_mapped(migrated):
    unmapped_tables = sorted(set(migrated) - set(COLUMN_MAP) - set(TABLE_MAP))
    assert unmapped_tables == [], "map these tables in dtvp/backup/entities.py"
    stale_tables = sorted((set(COLUMN_MAP) | set(TABLE_MAP)) - set(migrated))
    assert stale_tables == []
    assert not set(COLUMN_MAP) & set(TABLE_MAP)
    for table, columns in COLUMN_MAP.items():
        assert sorted(set(columns) - set(migrated[table])) == [], f"stale columns of {table}"
        assert sorted(set(migrated[table]) - set(columns)) == [], f"unmapped columns of {table}"
    for reason in [*TABLE_MAP.values(), *(m for c in COLUMN_MAP.values() for m in c.values())]:
        kind = reason.split(":", 1)[0]
        assert kind in {"field", "derived", "storage", "lookup", "cache", "marker", "excluded"}
        assert reason.split(":", 1)[1].strip()


def test_every_entity_reads_a_mapped_table():
    for spec in entities.ENTITIES.values():
        if spec.table is not None:
            assert spec.table in COLUMN_MAP
            assert any(
                value.startswith(f"field: {spec.name}.")
                for value in COLUMN_MAP[spec.table].values()
            )


_DATA_CHANGE = re.compile(r"\b(INSERT|UPDATE|DELETE)\b", re.IGNORECASE)


def _strip_comments(sql: str) -> str:
    return "\n".join(line.split("--", 1)[0] for line in sql.splitlines())


def test_every_data_changing_migration_has_a_record_effect():
    changing = set()
    known = set()
    for namespace, migrations_path in MIGRATION_PATHS.items():
        for migration in load_sqlite_migrations(migrations_path()):
            known.add((namespace, migration.version))
            if _DATA_CHANGE.search(_strip_comments(migration.sql)):
                changing.add((namespace, migration.version))
    effects = migration_effects.MIGRATION_RECORD_EFFECTS
    missing = sorted(changing - set(effects))
    assert missing == [], "add these to dtvp/backup/migration_effects.py"
    assert sorted(set(effects) - known) == []
    for key, effect in effects.items():
        assert isinstance(
            effect,
            (migration_effects.Baseline, migration_effects.NoRecordEffect, migration_effects.Upcaster),
        ), key
        if isinstance(effect, migration_effects.Upcaster):
            assert (effect.entity, effect.from_version) in upcasters.UPCASTERS, key
        if isinstance(effect, migration_effects.NoRecordEffect):
            assert effect.reason


def test_the_effects_table_names_todays_baseline():
    assert {
        key
        for key, effect in migration_effects.MIGRATION_RECORD_EFFECTS.items()
        if isinstance(effect, migration_effects.Baseline)
    } == {
        ("local_store", 2),
        ("assessment_outbox", 3),
        ("assessment_outbox", 4),
        ("assessment_outbox", 6),
        ("assessment_outbox", 7),
        ("assessment_outbox", 8),
    }


def test_an_upcaster_effect_needs_its_upcaster(monkeypatch):
    monkeypatch.setitem(
        migration_effects.MIGRATION_RECORD_EFFECTS,
        ("assessment_outbox", 8),
        migration_effects.Upcaster("assessment", 1),
    )
    with pytest.raises(AssertionError):
        test_every_data_changing_migration_has_a_record_effect()
