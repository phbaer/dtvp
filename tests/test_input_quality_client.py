"""Input-quality CLI uses backend full counts and exact pinned scope."""

import sys

import httpx
import respx

from dtvp.cli import main


@respx.mock
def test_input_quality_cli_forwards_selection_and_keeps_full_counts(monkeypatch, capsys):
    monkeypatch.delenv("DTVP_API_TOKEN", raising=False)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "dtvp",
            "knowledge",
            "--url",
            "http://dtvp.test",
            "input-quality",
            "--project",
            "project",
            "--state",
            "a" * 64,
            "--code",
            "license_unknown",
            "--q",
            "package",
            "--limit",
            "1",
        ],
    )
    route = respx.get(
        "http://dtvp.test/api/v3/projects/project/states/" + "a" * 64 + "/input-quality"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "state": "a" * 64,
                "report_digest": "b" * 64,
                "statistics": {
                    "occurrences": 100,
                    "by_role": {"inventory_component": 99, "metadata_root": 1},
                    "issues": 250,
                },
                "sources": [{"id": "baseline", "collection": {"package_coverage": "unknown"}}],
                "items": [
                    {
                        "code": "license_unknown",
                        "component_ref": "package",
                        "source_id": "baseline",
                        "details": {},
                    }
                ],
                "total": 40,
                "next_offset": 1,
                "limitations": ["No correctness or license clearance is inferred."],
            },
        )
    )
    main()
    request = route.calls[0].request
    assert dict(request.url.params) == {
        "q": "package",
        "code": "license_unknown",
        "offset": "0",
        "limit": "1",
    }
    output = capsys.readouterr().out
    assert "All observations: 250 · Matching observations: 40" in output
    assert "not verified" in output and "No correctness or license clearance" in output
    assert "Next offset: 1" in output
