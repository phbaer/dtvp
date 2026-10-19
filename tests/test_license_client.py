"""CLI forwards pinned selection without recomputing license clearance."""

import json
import sys

import httpx
import pytest
import respx

from dtvp.cli import main


@pytest.mark.parametrize("as_json", [False, True])
@respx.mock
def test_license_cli_forwards_selection(monkeypatch, capsys, as_json):
    monkeypatch.delenv("DTVP_API_TOKEN", raising=False)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "dtvp",
            "knowledge",
            "--url",
            "http://dtvp.test",
            "licenses",
            "--project",
            "product/name",
            "--state",
            "a" * 64,
            "--q",
            "MIT",
            "--evidence-status",
            "reported",
            "--review-status",
            "pending",
            "--approved-disposition",
            "restricted",
            "--offset",
            "20",
            "--limit",
            "10",
        ]
        + (["--json"] if as_json else []),
    )
    result = {
        "state": "a" * 64,
        "total": 2,
        "statistics": {"components": 2},
        "items": [
            {
                "component_ref": "lib",
                "component": {"name": "Library"},
                "evidence": {"status": "reported"},
                "license_review": {
                    "status": "approved",
                    "approved": True,
                    "assessment": {"payload": {"disposition": "allowed"}},
                    "approved_assessment": {"payload": {"disposition": "restricted"}},
                },
            }
        ],
        "next_offset": 30,
    }
    route = respx.get(
        "http://dtvp.test/api/v1/projects/product%2Fname/states/" + "a" * 64 + "/license-worklist"
    ).mock(return_value=httpx.Response(200, json=result))
    main()
    assert dict(route.calls[0].request.url.params) == {
        "q": "MIT",
        "evidence_status": "reported",
        "review_status": "pending",
        "approved_disposition": "restricted",
        "offset": "20",
        "limit": "10",
    }
    output = capsys.readouterr().out
    if as_json:
        assert json.loads(output) == result
    else:
        assert "approved_disposition=restricted" in output and "Next offset: 30" in output
        assert "approved_disposition=allowed" not in output
