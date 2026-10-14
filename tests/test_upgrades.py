import json

from alembic import command
from alembic.config import Config
from sqlalchemy import text

from dtvp.db import ROOT, engine_for, migrate, schema_ready


def test_previous_schema_is_backed_up_and_upgraded_implicitly(tmp_path):
    engine = engine_for("sqlite:///:memory:")
    config = Config(str(ROOT / "alembic.ini"))
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "0001")
        connection.execute(
            text(
                "INSERT INTO workspaces(id, name, created_at) VALUES ('team', 'Preserved team', '2026-01-01')"
            )
        )
    migrate(engine, tmp_path / "backups")
    assert schema_ready(engine)
    with engine.connect() as connection:
        assert (
            connection.scalar(text("SELECT name FROM workspaces WHERE id='team'"))
            == "Preserved team"
        )
    backups = list((tmp_path / "backups").glob("*.jsonl"))
    assert len(backups) == 1
    records = [json.loads(line) for line in backups[0].read_text().splitlines()]
    assert any(
        record["table"] == "workspaces" and record["row"]["name"] == "Preserved team"
        for record in records
    )
    assert json.loads(backups[0].with_suffix(".manifest.json").read_text())["schema"] == "0001"
    migrate(engine, tmp_path / "backups")
    assert len(list((tmp_path / "backups").glob("*.jsonl"))) == 1


def test_attachment_context_and_access(analyst, release_id):
    from tests.conftest import login

    content = b"<ThreatModel>synthetic opaque context</ThreatModel>"
    result = analyst.post(
        f"/api/v2/releases/{release_id}/attachments",
        files={"file": ("demo.tm7", content)},
        data={"kind": "threat_model"},
    )
    assert result.status_code == 201
    sha = result.json()["sha256"]
    assert analyst.get(f"/api/v2/releases/{release_id}/attachments/{sha}").content == content
    login(analyst, "operations")
    assert analyst.get(f"/api/v2/releases/{release_id}/attachments/{sha}").status_code == 404
