import json
import sys

import httpx
import pytest
import respx

from dtvp.cli import main


@pytest.mark.parametrize("structured", [False, True])
@respx.mock
def test_cli_uses_only_server_identity_report(monkeypatch, capsys, structured):
    report = {
        "report_digest": "c" * 64,
        "summary": {"matched": 1, "unresolved": 0},
        "items": [{"basis": "exact_purl", "source_id": "old", "target_id": "new"}],
        "next_offset": None,
    }
    route = respx.get(
        "http://dtvp.test/api/v1/projects/product%2Fname/states/" + "b" * 64 + "/identity-matches",
        params={"source": "a" * 64, "offset": "0", "limit": "50"},
    ).mock(return_value=httpx.Response(200, json=report))
    monkeypatch.delenv("DTVP_API_TOKEN", raising=False)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "dtvp",
            "knowledge",
            "--url",
            "http://dtvp.test",
            "identity-matches",
            "--project",
            "product/name",
            "--source",
            "a" * 64,
            "--target",
            "b" * 64,
        ]
        + (["--json"] if structured else []),
    )
    main()
    assert route.call_count == 1
    output = capsys.readouterr().out
    if structured:
        assert json.loads(output) == report
    else:
        assert "old -> new" in output
        assert "Read-only" in output
