"""CLI forwards selectors and pins; the backend alone orders product labels."""

import json
import sys

import httpx
import pytest
import respx

from dtvp.cli import main


@pytest.mark.parametrize("filtered", [False, True])
@respx.mock
def test_coverage_cli_preserves_default_body_and_forwards_closed_selection(
    monkeypatch, capsys, filtered
):
    monkeypatch.delenv("DTVP_API_TOKEN", raising=False)
    args = [
        "dtvp",
        "knowledge",
        "--url",
        "http://dtvp.test",
        "coverage",
        "--project",
        "product/name",
        "--state",
        "a" * 64,
        "--context",
        "b" * 64,
        "--vulnerability",
        "CVE-2099-1",
        "--expected-preview",
        "c" * 64,
        "--json",
    ]
    if filtered:
        args += [
            "--version-from",
            "7.1.1",
            "--version-through",
            "7.2.0",
            "--exclude-version",
            "7.1.2",
            "--include-version",
            "main",
        ]
    monkeypatch.setattr(sys, "argv", args)
    response = {"preview_digest": "c" * 64, "items": []}
    route = respx.post("http://dtvp.test/api/v1/projects/product%2Fname/coverage/candidates").mock(
        return_value=httpx.Response(200, json=response)
    )
    main()
    body = json.loads(route.calls[0].request.content)
    expected = {
        "source": "a" * 64,
        "context_id": "b" * 64,
        "vulnerability_id": "CVE-2099-1",
        "expected_preview": "c" * 64,
    }
    if filtered:
        expected["version_selection"] = {
            "lower": "7.1.1",
            "upper": "7.2.0",
            "include": ["main"],
            "exclude": ["7.1.2"],
        }
    assert body == expected
    assert json.loads(capsys.readouterr().out) == response
