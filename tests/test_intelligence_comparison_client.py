"""CLI forwards immutable pins and never fetches latest evidence implicitly."""

import json
import sys

import httpx
import pytest
import respx

from dtvp.cli import main


@pytest.mark.parametrize("empty", [False, True])
@respx.mock
def test_cli_explicit_evidence_selection(monkeypatch, capsys, empty):
    monkeypatch.delenv("DTVP_API_TOKEN", raising=False)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "dtvp",
            "knowledge",
            "--url",
            "http://dtvp.test",
            "compare-intelligence",
            "--project",
            "product/name",
            "--state",
            "a" * 64,
            "--expected-digest",
            "c" * 64,
            "--json",
        ]
        + (["--no-evidence"] if empty else ["--evidence-state", "b" * 64]),
    )
    result = {"items": [], "report_digest": "c" * 64}
    route = respx.post("http://dtvp.test/api/v3/projects/product%2Fname/compare/intelligence").mock(
        return_value=httpx.Response(200, json=result)
    )
    main()
    assert json.loads(route.calls[0].request.content) == {
        "inventory_state": "a" * 64,
        "evidence_state": None if empty else "b" * 64,
        "expected_digest": "c" * 64,
    }
    assert json.loads(capsys.readouterr().out) == result
