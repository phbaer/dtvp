"""Dedicated CLI paths preserve server plans, explicit scope and uncertain retries."""

import json
import sys

import pytest
import respx

from dtvp.cli import main

ROOT = "http://dtvp.test/api/v1/projects/product"


def invoke(monkeypatch, *args):
    monkeypatch.delenv("DTVP_API_TOKEN", raising=False)
    monkeypatch.setattr(sys, "argv", ["dtvp", "knowledge", "--url", "http://dtvp.test", *args])
    main()


def plan(discovery):
    common = {
        "expected_versions": {"1.0": "a" * 64},
        "expected_evidence": "b" * 64,
        "total": 21,
        "next_offset": 20,
        "capabilities": ["query" if discovery else "refresh"],
        "limitations": ["No approval implied"],
    }
    if discovery:
        return {
            **common,
            "enabled": True,
            "next_revision": 4,
            "purls": ["pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"],
            "coverage": {"unsupported_occurrences": {"missing_purl": 2}},
        }
    return {
        **common,
        "providers": [{"id": "nvd", "enabled": True, "next_revision": 7, "publisher": "NVD"}],
        "identifiers": ["CVE-2021-44228"],
    }


@pytest.mark.parametrize("operation", ["discover", "enrich"])
@respx.mock
def test_plan_capture_and_uncertain_queue_replay_keep_exact_pins(
    monkeypatch, tmp_path, capsys, operation
):
    discovery = operation == "discover"
    data = plan(discovery)
    endpoint = ROOT + ("/osv-matching" if discovery else "/advisory-refresh")
    route = respx.get(endpoint).respond(200, json=data)
    output = tmp_path / "request.json"
    selection = (
        ["--purl", data["purls"][0]]
        if discovery
        else ["--provider", "nvd", "--id", "CVE-2021-44228"]
    )
    invoke(
        monkeypatch, operation, "plan", "--project", "product", *selection, "--output", str(output)
    )
    capture = json.loads(output.read_text())
    assert capture["input"]["expected_versions"] == data["expected_versions"]
    assert capture["input"]["expected_evidence"] == "b" * 64
    assert capture["input"]["revision"] == (4 if discovery else 7)
    assert "Next offset: 20" in capsys.readouterr().out
    jobs = respx.post(ROOT + ("/osv-jobs" if discovery else "/advisory-jobs")).respond(
        503, json={"detail": "Uncertain"}
    )
    with pytest.raises(SystemExit):
        invoke(monkeypatch, operation, "queue", "--project", "product", "--file", str(output))
    assert jobs.call_count == 1
    jobs.respond(202, json={"id": "queued", "status": "queued"})
    invoke(monkeypatch, operation, "queue", "--project", "product", "--file", str(output))
    assert jobs.calls[0].request.content == jobs.calls[1].request.content
    assert json.loads(jobs.calls[1].request.content) == capture["input"]
    assert route.call_count == 1  # Queuing never silently inspects/repins current state.
    assert json.loads(output.read_text()) == capture
    with pytest.raises(SystemExit):
        invoke(
            monkeypatch,
            operation,
            "plan",
            "--project",
            "product",
            *selection,
            "--output",
            str(output),
        )
    assert json.loads(output.read_text()) == capture


@pytest.mark.parametrize("operation", ["discover", "enrich"])
@respx.mock
def test_read_plans_and_job_status_do_not_enqueue(monkeypatch, capsys, operation):
    discovery = operation == "discover"
    data = plan(discovery)
    route = respx.get(ROOT + ("/osv-matching" if discovery else "/advisory-refresh")).respond(
        200, json=data
    )
    invoke(monkeypatch, operation, "plan", "--project", "product", "--offset", "20", "--json")
    assert json.loads(capsys.readouterr().out) == data
    assert route.calls[0].request.url.params["offset"] == "20"
    result = {"id": "job", "status": "succeeded", "result": {"projection": "current"}}
    respx.get(ROOT + ("/osv-jobs/job" if discovery else "/advisory-jobs/job")).respond(
        200, json=result
    )
    invoke(monkeypatch, operation, "jobs", "--project", "product", "--job", "job", "--json")
    assert json.loads(capsys.readouterr().out) == result
    assert all(call.request.method == "GET" for call in respx.calls)


@respx.mock
def test_disabled_provider_cannot_be_captured_and_cross_product_file_cannot_queue(
    monkeypatch, tmp_path
):
    data = {**plan(True), "enabled": False}
    respx.get(ROOT + "/osv-matching").respond(200, json=data)
    output = tmp_path / "request.json"
    with pytest.raises(SystemExit):
        invoke(
            monkeypatch,
            "discover",
            "plan",
            "--project",
            "product",
            "--purl",
            data["purls"][0],
            "--output",
            str(output),
        )
    assert not output.exists()
    output.write_text(
        json.dumps(
            {
                "format": "dtvp.vulnerability-request/1",
                "operation": "discover",
                "project_id": "other",
                "input": {},
            }
        )
    )
    with pytest.raises(SystemExit):
        invoke(monkeypatch, "discover", "queue", "--project", "product", "--file", str(output))
    assert all(call.request.method == "GET" for call in respx.calls)


@pytest.mark.parametrize(
    "values", [[], ["pkg:pypi/a@1"] * 2, [f"pkg:pypi/a@{n}" for n in range(21)]]
)
@respx.mock
def test_capture_needs_bounded_explicit_selection(monkeypatch, tmp_path, values):
    with pytest.raises(SystemExit):
        invoke(
            monkeypatch,
            "discover",
            "plan",
            "--project",
            "product",
            *[arg for value in values for arg in ("--purl", value)],
            "--output",
            str(tmp_path / "request.json"),
        )
    assert not respx.calls
