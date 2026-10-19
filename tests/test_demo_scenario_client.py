"""The CLI transports editable demo files; all workflow decisions remain server-side."""

import json
import sys
from pathlib import Path

import httpx
import pytest
import respx

from dtvp.cli import main


@respx.mock
def test_demo_cli_sends_complete_file_and_synthetic_session(monkeypatch, capsys):
    monkeypatch.delenv("DTVP_API_TOKEN", raising=False)
    source = Path(__file__).parent.parent / "playground/scenarios/workflow.json"
    login = respx.post("http://demo.test/api/v1/playground/login").mock(
        return_value=httpx.Response(
            200, json={}, headers={"set-cookie": "dtvp_csrf=scenario-csrf; Path=/"}
        )
    )
    loaded = respx.post("http://demo.test/api/v1/playground/knowledge/load").mock(
        return_value=httpx.Response(
            200,
            json={"fixture_id": "native-workflow/1", "synthetic": True, "preserved_existing": True},
        )
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "dtvp",
            "knowledge",
            "--url",
            "http://demo.test",
            "--persona",
            "administrator",
            "demo",
            "load",
            "--file",
            str(source),
        ],
    )
    main()
    assert json.loads(login.calls[0].request.content) == {"persona": "administrator"}
    assert json.loads(loaded.calls[0].request.content) == json.loads(source.read_bytes())
    assert loaded.calls[0].request.headers["X-CSRF-Token"] == "scenario-csrf"
    assert '"preserved_existing": true' in capsys.readouterr().out


@respx.mock
def test_demo_cli_requires_an_explicit_synthetic_persona(monkeypatch, tmp_path):
    import argparse

    from dtvp.knowledge.client import configure, run

    monkeypatch.delenv("DTVP_API_TOKEN", raising=False)
    path = tmp_path / "scenario.json"
    path.write_text("{}")
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command")
    configure(commands)
    args = parser.parse_args(["knowledge", "demo", "load", "--file", str(path)])
    with pytest.raises(ValueError, match="--persona"):
        run(args)
    assert not respx.calls
