"""CLI presents authoritative summary bytes/counts without local release policy."""

import json
import sys

import httpx
import pytest
import respx

from dtvp.cli import main


@pytest.mark.parametrize("as_json", [False, True])
@respx.mock
def test_cli_reads_exact_state_without_computing_a_gate(monkeypatch, capsys, as_json):
    monkeypatch.delenv("DTVP_API_TOKEN", raising=False)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "dtvp",
            "knowledge",
            "--url",
            "http://dtvp.test",
            "evidence-summary",
            "--project",
            "product/name",
            "--state",
            "a" * 64,
        ]
        + (["--json"] if as_json else []),
    )
    result = {
        "state": "a" * 64,
        "summary_digest": "b" * 64,
        "inventory": {"baseline_status": "withdrawn"},
        "vulnerabilities": {"totals": {"context_findings": 203, "approved": 0}},
        "licenses": {"current_approved_components": 0},
        "documents": {"current_approved": 0},
        "retained": {"retained_absent_assessments": 8},
        "limitations": [
            {"code": "no_release_verdict", "description": "No automatic release verdict."}
        ],
    }
    route = respx.get(
        "http://dtvp.test/api/v1/projects/product%2Fname/states/" + "a" * 64 + "/evidence-summary"
    ).mock(return_value=httpx.Response(200, json=result))
    main()
    assert route.call_count == 1 and not route.calls[0].request.url.query
    output = capsys.readouterr().out
    if as_json:
        assert json.loads(output) == result
    else:
        assert "203" in output and "withdrawn" in output and "no_release_verdict" in output
