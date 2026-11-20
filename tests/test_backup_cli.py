"""The command line: python -m dtvp.backup."""

import json
import os
import subprocess
import sys

import pytest

from dtvp.backup.__main__ import main
from tests.backup_instance import configure_instance, populate
from tests.dump_helpers import FIXTURE_V1, build_dump, pack_tree


@pytest.fixture
def instance(tmp_path, monkeypatch):
    configured = configure_instance(monkeypatch, tmp_path / "instance")
    populate(configured)
    return configured


def test_export_verify_inspect(instance, capsys):
    assert main(["export", "--label", "site"]) == 0
    out, err = capsys.readouterr()
    path = out.strip()
    assert os.path.basename(path).startswith("site-")
    assert "payload_raw" in err
    assert main(["verify", path]) == 0
    out, err = capsys.readouterr()
    assert out.startswith("OK: dump ")
    assert main(["inspect", path, "--json"]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["records"]["assessment"] == 7
    assert main(["inspect", path]) == 0
    assert "Contains credentials: no" in capsys.readouterr().out


def test_export_with_tokens_warns(instance, capsys, tmp_path):
    target = tmp_path / "out" / "x.zip"
    assert main(["export", "--out", str(target), "--include-access-tokens"]) == 0
    _out, err = capsys.readouterr()
    assert "access-token digests" in err
    assert target.exists() and (tmp_path / "out" / "x.zip.sha256").exists()


def test_refusals_exit_with_1(instance, capsys, tmp_path):
    (instance.dt_cache / ".dtvp-restore-1.json").write_text("{}")
    assert main(["export"]) == 1
    assert "E6" in capsys.readouterr().err
    broken = build_dump(
        tmp_path / "broken.zip",
        change_manifest=lambda m: m["cut_point"]["sequences"].update(assessment_revisions=0),
    )
    assert main(["verify", str(broken)]) == 1
    assert "R6" in capsys.readouterr().err
    (tmp_path / "junk.zip").write_bytes(b"junk")
    assert main(["inspect", str(tmp_path / "junk.zip")]) == 1
    assert main(["verify", str(tmp_path / "missing.zip")]) == 1


def test_usage_errors_exit_with_2(capsys):
    assert main([]) == 2
    assert main(["export", "--out", "a", "--dir", "b"]) == 2
    assert main(["frobnicate"]) == 2


def test_module_entry_point(tmp_path):
    path = pack_tree(FIXTURE_V1, tmp_path / "fixture.zip")
    completed = subprocess.run(
        [sys.executable, "-m", "dtvp.backup", "verify", str(path)],
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert "OK" in completed.stdout
