import json

import pytest

from dtvp.knowledge.journal import SECTIONS, CorruptJournal, Journal
from dtvp.knowledge.verification import verify_journal
from tests.test_knowledge_journal import publish, state


def test_checks_old_publications_and_unpublished_parents_but_not_orphans(tmp_path):
    journal = Journal(tmp_path / "journal")
    artifact = journal.objects.put(b"original")
    parent = journal.snapshot(
        project_id="product",
        version="7.1.1",
        actor_id="author",
        reason="parent",
        sections={key: {} for key in SECTIONS},
        artifacts=[artifact],
    )
    first = state(journal, parent=parent)
    publish(journal, first)
    latest = state(journal, parent=first)
    publish(journal, latest, expected=first, request_id="replace")
    orphan = journal.objects.put(b"uncommitted")
    journal.objects.path(orphan).write_bytes(b"bad orphan")
    result = verify_journal(journal)
    assert result["head"] == journal.head()
    assert result["publications"] == 2
    assert result["states"] == 3
    assert result["objects"] > 3 and result["bytes"] > 0
    journal.objects.path(artifact).unlink()
    with pytest.raises(CorruptJournal, match="corrupt or missing"):
        verify_journal(journal)


def test_empty_and_corrupt_history_fail_closed(tmp_path):
    journal = Journal(tmp_path / "journal")
    assert verify_journal(journal) == {
        "head": None,
        "publications": 0,
        "states": 0,
        "objects": 0,
        "bytes": 0,
    }
    first = state(journal)
    publish(journal, first)
    section = journal.state(first).sections["inventory"]
    journal.objects.path(section).write_bytes(b"corrupt")
    with pytest.raises(CorruptJournal):
        verify_journal(journal)


def test_offline_command_requires_existing_journal_and_never_opens_sql(
    tmp_path, monkeypatch, capsys
):
    from dtvp import cli

    directory = tmp_path / "journal"
    monkeypatch.setattr("sys.argv", ["dtvp", "verify-knowledge", "--directory", str(directory)])
    monkeypatch.setattr(cli, "engine_for", lambda *args: pytest.fail("SQL must not be opened"))
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 1
    assert not directory.exists()
    Journal(directory)
    cli.main()
    assert json.loads(capsys.readouterr().out)["publications"] == 0
