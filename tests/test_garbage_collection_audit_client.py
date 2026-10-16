import json
import sys

import pytest

from dtvp.knowledge.garbage_collection import main
from dtvp.knowledge.journal import Journal


def test_operator_audit_does_not_create_missing_journal(monkeypatch, tmp_path):
    path = tmp_path / "missing"
    monkeypatch.setattr(sys, "argv", ["audit", "--journal", str(path)])
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 2
    assert not path.exists()


def test_operator_audit_never_advertises_execution(monkeypatch, tmp_path, capsys):
    journal = Journal(tmp_path / "journal")
    sha = journal.objects.put(b"unpublished operation input")
    monkeypatch.setattr(
        sys, "argv", ["audit", "--journal", str(journal.root), "--min-age-days", "7"]
    )
    main()
    result = json.loads(capsys.readouterr().out)
    assert result["items"][0]["sha256"] == sha
    assert result["execution_supported"] is False
    assert result["operational_references_complete"] is False
    assert result["statistics"]["eligible_for_deletion"] == 0
    assert journal.objects.read(sha) == b"unpublished operation input"
    assert journal.head() is None
