"""Scoring commands transport pinned requests without making coordinator decisions."""

import json
import sys

import httpx
import pytest
import respx

from dtvp.api_contract import API_PREFIX
from dtvp.cli import main


@pytest.mark.parametrize(
    ("action", "rules", "method", "suffix", "with_file"),
    [
        ("policy", False, "GET", "/scoring-policy", False),
        ("policy", False, "PUT", "/scoring-policy", True),
        ("preview", False, "POST", "/scoring/preview", True),
        ("publish", False, "POST", "/scoring/publish", True),
        ("preview", True, "POST", "/scoring/rules/preview", True),
        ("publish", True, "POST", "/scoring/rules/publish", True),
    ],
)
@respx.mock
def test_scoring_commands_forward_exact_json(
    monkeypatch, tmp_path, capsys, action, rules, method, suffix, with_file
):
    monkeypatch.setenv("DTVP_API_TOKEN", "local-test-token")
    payload = {
        "request_id": "operator-request",
        "expected_versions": {"7.1.2": "a" * 64},
        "preview": "b" * 64,
        "rationale": "Explicit operator decision",
    }
    source = tmp_path / "request.json"
    source.write_text(json.dumps(payload))
    route = respx.request(
        method, "http://score.test" + API_PREFIX + "/projects/product" + suffix
    ).mock(return_value=httpx.Response(200, json={"received": True}))
    args = [
        "dtvp",
        "knowledge",
        "--url",
        "http://score.test",
        "score",
        action,
        "--project",
        "product",
    ]
    if with_file:
        args += ["--file", str(source)]
    if rules:
        args += ["--rules"]
    monkeypatch.setattr(sys, "argv", args)
    main()
    assert len(route.calls) == 1
    request = route.calls[0].request
    assert request.headers["Authorization"] == "Bearer local-test-token"
    assert json.loads(request.content) == payload if with_file else not request.content
    assert json.loads(capsys.readouterr().out) == {"received": True}


@respx.mock
def test_scoring_rejects_nonobject_without_publishing(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("DTVP_API_TOKEN", "local-test-token")
    source = tmp_path / "request.json"
    source.write_text("[]")
    monkeypatch.setattr(
        sys,
        "argv",
        ["dtvp", "knowledge", "score", "publish", "--project", "product", "--file", str(source)],
    )
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 1
    assert "JSON object" in capsys.readouterr().err
    assert not respx.calls


@pytest.mark.parametrize("action", ["draft", "submit", "review"])
@respx.mock
def test_assessment_and_review_wrappers_forward_exact_pinned_payload(monkeypatch, tmp_path, action):
    monkeypatch.setenv("DTVP_API_TOKEN", "local-test-token")
    payload = {
        "request_id": "explicit",
        "expected_versions": {"7.1.2": "a" * 64},
        "ssvc": {"model": "explicit-only"},
        "action": "request_changes",
    }
    source = tmp_path / "review.json"
    source.write_text(json.dumps(payload))
    suffix = "/reviews" if action == "review" else "/assessments/decision/" + action
    route = respx.post("http://scope.test" + API_PREFIX + "/projects/project" + suffix).mock(
        return_value=httpx.Response(201, json={"committed": True})
    )
    args = ["dtvp", "knowledge", "--url", "http://scope.test"]
    args += ["review"] if action == "review" else ["assessment", action, "--id", "decision"]
    args += ["--project", "project", "--file", str(source)]
    monkeypatch.setattr(sys, "argv", args)
    main()
    assert json.loads(route.calls[0].request.content) == payload
