"""CLI forwards exact preview/apply input; no local mapping or approvals."""

import json
import sys

import httpx
import pytest
import respx

from dtvp.cli import main


@pytest.mark.parametrize("apply", [False, True])
@respx.mock
def test_cli_forwards_exact_explicit_request(monkeypatch, capsys, tmp_path, apply):
    data = {
        "source": "a" * 64,
        "target": "b" * 64,
        "assertions": {"mapping": "c" * 64},
        "request_id": "stable",
    }
    path = tmp_path / "request.json"
    path.write_text(json.dumps(data))
    monkeypatch.delenv("DTVP_API_TOKEN", raising=False)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "dtvp",
            "knowledge",
            "--url",
            "http://dtvp.test",
            "correspondence-draft",
            "--project",
            "product/name",
            "--input",
            str(path),
        ]
        + (["--apply"] if apply else []),
    )
    result = {"category": "needs_review", "requires_new_target_review": True}
    route = respx.post(
        "http://dtvp.test/api/v3/projects/product%2Fname/correspondence-drafts"
        + ("" if apply else "/preview")
    ).mock(return_value=httpx.Response(201 if apply else 200, json=result))
    main()
    assert route.call_count == 1
    assert json.loads(route.calls[0].request.content) == data
    assert json.loads(capsys.readouterr().out) == result
