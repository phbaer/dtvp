"""Implicit upgrade adds operational pacing without changing owned application data."""

from alembic import command
from alembic.config import Config
from sqlalchemy import insert, inspect, select

from dtvp.db import ROOT, engine_for, migrate, schema_ready
from dtvp.models import AdvisoryProviderThrottle, Workspace


def test_prior_schema_upgrades_with_backup_and_retained_rows(tmp_path):
    engine = engine_for("sqlite:///" + str(tmp_path / "old.db"))
    config = Config(str(ROOT / "alembic.ini"))
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "0005")
        connection.execute(insert(Workspace).values(id="retained", name="Existing team"))
    assert not schema_ready(engine)
    migrate(engine, backup_dir=tmp_path / "backups")
    assert schema_ready(engine)
    assert "advisory_provider_throttles" in inspect(engine).get_table_names()
    with engine.begin() as connection:
        assert (
            connection.scalar(select(Workspace.name).where(Workspace.id == "retained"))
            == "Existing team"
        )
        connection.execute(insert(AdvisoryProviderThrottle).values(provider="nvd"))
    migrate(engine, backup_dir=tmp_path / "backups")
    with engine.connect() as connection:
        assert connection.scalar(select(AdvisoryProviderThrottle.provider)) == "nvd"
    assert list((tmp_path / "backups").iterdir())
    engine.dispose()
