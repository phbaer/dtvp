"""Configuration CLI forwards server-owned contracts without local decisions."""

import json
import sys

import httpx
import pytest
import respx

from dtvp.cli import main


@pytest.mark.parametrize("command", ["pipeline-config", "synchronization-policy"])
@respx.mock
def test_configuration_get_and_exact_explicit_put(command, monkeypatch, tmp_path, capsys):
    monkeypatch.delenv("DTVP_API_TOKEN", raising=False)
    arguments = ["dtvp", "knowledge", "--url", "http://dtvp.test", command, "--project", "project"]
    path = "http://dtvp.test/api/v3/projects/project/" + command
    read = respx.get(path).mock(return_value=httpx.Response(200, json={"state": "frozen"}))
    monkeypatch.setattr(sys, "argv", arguments)
    main()
    assert read.called and json.loads(capsys.readouterr().out) == {"state": "frozen"}
    data = {"request_id": "retained", "expected_policy": "a" * 64, "relationships": []}
    source = tmp_path / "request.json"
    source.write_text(json.dumps(data))
    write = respx.put(path).mock(return_value=httpx.Response(201, json={"committed": True}))
    monkeypatch.setattr(sys, "argv", arguments + ["--input", str(source)])
    main()
    assert json.loads(write.calls[0].request.content) == data


@pytest.mark.parametrize(
    "action,method", [(None, "GET"), ("proposal", "GET"), ("retry", "POST"), ("cancel", "POST")]
)
@respx.mock
def test_jobs_are_explicit_presentational_operations(action, method, monkeypatch, capsys):
    monkeypatch.delenv("DTVP_API_TOKEN", raising=False)
    arguments = [
        "dtvp",
        "knowledge",
        "--url",
        "http://dtvp.test",
        "synchronization-jobs",
        "--project",
        "project",
        "--job",
        "job",
    ]
    if action:
        arguments += ["--action", action]
    path = "http://dtvp.test/api/v3/projects/project/synchronization-jobs/job" + (
        "/" + action if action else ""
    )
    route = respx.request(method, path).mock(return_value=httpx.Response(200, json={"id": "job"}))
    monkeypatch.setattr(sys, "argv", arguments)
    main()
    assert route.called and json.loads(capsys.readouterr().out) == {"id": "job"}


@respx.mock
def test_context_forwards_both_pins(monkeypatch):
    monkeypatch.delenv("DTVP_API_TOKEN", raising=False)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "dtvp",
            "knowledge",
            "--url",
            "http://dtvp.test",
            "pipeline-context",
            "--project",
            "project",
            "--state",
            "a" * 64,
            "--configuration",
            "b" * 64,
        ],
    )
    route = respx.get(
        "http://dtvp.test/api/v3/projects/project/states/" + "a" * 64 + "/pipeline-context"
    ).mock(return_value=httpx.Response(200, json={}))
    main()
    assert route.calls[0].request.url.params["configuration"] == "b" * 64


@pytest.mark.parametrize("apply", [False, True])
@respx.mock
def test_observation_selection_is_preview_unless_explicitly_applied(apply, monkeypatch, tmp_path):
    monkeypatch.delenv("DTVP_API_TOKEN", raising=False)
    data = {"request_id": "exact", "expected": "a" * 64, "configuration": "b" * 64}
    source = tmp_path / "selection.json"
    source.write_text(json.dumps(data))
    arguments = [
        "dtvp",
        "knowledge",
        "--url",
        "http://dtvp.test",
        "observation-selection",
        "--project",
        "project",
        "--version",
        "7.1.2",
        "--input",
        str(source),
    ]
    if apply:
        arguments.append("--apply")
    route = respx.post(
        "http://dtvp.test/api/v3/projects/project/versions/7.1.2/observation-selection"
        + ("" if apply else "/preview")
    ).mock(return_value=httpx.Response(200, json={}))
    monkeypatch.setattr(sys, "argv", arguments)
    main()
    assert json.loads(route.calls[0].request.content) == data


@respx.mock
def test_observation_import_preserves_file_bytes_and_metadata(monkeypatch, tmp_path):
    monkeypatch.delenv("DTVP_API_TOKEN", raising=False)
    data = {"source": "scanner", "request_id": "exact", "expected": None}
    metadata = tmp_path / "metadata.json"
    metadata.write_text(json.dumps(data))
    source = tmp_path / "original.json"
    raw = b'{\n  "bomFormat": "CycloneDX"\n}\n'
    source.write_bytes(raw)
    route = respx.post(
        "http://dtvp.test/api/v3/projects/project/versions/7.1.2/observation-files"
    ).mock(return_value=httpx.Response(201, json={}))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "dtvp",
            "knowledge",
            "--url",
            "http://dtvp.test",
            "observation-import",
            "--project",
            "project",
            "--version",
            "7.1.2",
            "--input",
            str(metadata),
            "--file",
            str(source),
        ],
    )
    main()
    body = route.calls[0].request.content
    assert raw in body and json.dumps(data).encode() in body
