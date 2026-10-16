"""CLI forwards received-evidence predicates without local reinterpretation."""

import sys

import httpx
import pytest
import respx

from dtvp.cli import main


@pytest.mark.parametrize(
    "command,path,extra",
    [
        ("workspace", "/projects/p/versions/7.1.2/workspace", ["--version", "7.1.2"]),
        ("portfolio", "/projects/p/portfolio", []),
    ],
)
@respx.mock
def test_received_evidence_filters_reach_server(monkeypatch, capsys, command, path, extra):
    monkeypatch.delenv("DTVP_API_TOKEN", raising=False)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "dtvp",
            "knowledge",
            "--url",
            "http://dtvp.test",
            command,
            "--project",
            "p",
            *extra,
            "--agentyzer-evidence",
            "historical_only",
            "--vscorer-evidence",
            "eligible",
            "--json",
        ],
    )
    route = respx.get("http://dtvp.test/api/v3" + path).mock(
        return_value=httpx.Response(200, json={"items": []})
    )
    main()
    assert route.calls[0].request.url.params["agentyzer_evidence"] == "historical_only"
    assert route.calls[0].request.url.params["vscorer_evidence"] == "eligible"
    assert '"items"' in capsys.readouterr().out
