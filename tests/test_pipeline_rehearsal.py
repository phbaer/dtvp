"""The interactive pipeline rehearsal exercises real API policy and byte contracts."""

import hashlib
import json

import httpx
import pytest

from scripts.knowledge_pipeline_rehearsal import rehearse
from tests.test_knowledge_api import app as knowledge_app

app = knowledge_app


@pytest.mark.parametrize("simulate_reviews", [False, True])
def test_pipeline_rehearsal_assembles_gates_reviews_and_archives_exact_issued_bytes(
    client, tmp_path, simulate_reviews
):
    output = tmp_path / "rehearsal"
    output.mkdir()
    report, files = rehearse(client, simulate_reviews=simulate_reviews, output=output)
    assert report["synthetic"] and report["simulated_reviews"] is simulate_reviews
    assert report["acceptance"] == "synthetic_contract_rehearsal_only"
    assert report["verified_consumer_files"] >= 2
    assert (report["initial_state"] != report["final_state"]) is simulate_reviews
    assert report["pipeline_configuration"]
    assert len(report["observation_states"]) == 2
    assert len(report["selection_states"]) == 3
    assert report["overlap"] == {
        "subject_assurance": "producer_declared",
        "inventory_implicitly_adopted": False,
        "withdrawn": True,
        "historical_source_bytes_verified": 2,
    }
    for build in (1, 2):
        metadata = json.loads(files[f"observation-{build}-import-metadata.json"])
        assert (
            metadata["subject_declaration"]["authority_sbom_sha256"]
            == hashlib.sha256(files["application.cdx.json"]).hexdigest()
        )
        assert (
            metadata["subject_declaration"]["observation_sbom_sha256"]
            == hashlib.sha256(files[f"observation-{build}.cdx.json"]).hexdigest()
        )
        preview = json.loads(files[f"observation-{build}-preview.json"])
        assert preview["human_decisions_changed"] is False
        assert preview["reports"][0]["report"]["summary"]["supplemental_assertions"] > 0
    bundle = json.loads(files["issued-bundle.json"])
    assert bundle["pipeline_context"]["configuration_state"] == report["pipeline_configuration"]
    assert any(row["status"] == "mapped" for row in bundle["pipeline_context"]["rows"])
    vscorer_context = json.loads(files["vscorer-pipeline-context.json"])
    assert vscorer_context["configuration_state"] == report["pipeline_configuration"]
    assert any(model["model_id"] == "synthetic-architecture" for model in vscorer_context["models"])
    summary = json.loads(files["evidence-summary.json"])
    assert summary["inventory"]["assembly"]["selected_parts"] == 2
    assert summary["licenses"]["current_approved_components"] == 0
    assert not json.loads(files["scoring-before-review.json"])["eligible"]
    if simulate_reviews:
        assert json.loads(files["scoring-after-review.json"])["eligible"]
        assert summary["vulnerabilities"]["scoring"]["published"] == 1
    else:
        assert not summary["vulnerabilities"]["scoring"].get("published")
    for name, metadata in report["files"].items():
        assert (output / name).read_bytes() == files[name]
        assert hashlib.sha256(files[name]).hexdigest() == metadata["sha256"]
    # New runs add a clearly named project; existing interactive work is untouched.
    second, _ = rehearse(client)
    assert second["project_id"] != report["project_id"]
    old = client.get(
        f"/api/v3/projects/{report['project_id']}/states/{report['final_state']}/evidence-summary"
    )
    assert old.json() == summary


def test_nonplayground_server_is_rejected_before_resource_writes():
    calls = []

    def server(request):
        calls.append(request.url.path)
        if request.url.path.endswith("/login"):
            return httpx.Response(200, json={}, headers={"set-cookie": "dtvp_csrf=synthetic"})
        return httpx.Response(200, json={"playground": False})

    with httpx.Client(
        base_url="http://example.test", transport=httpx.MockTransport(server)
    ) as client:
        with pytest.raises(ValueError, match="isolated playground"):
            rehearse(client)
    assert calls == ["/api/v2/playground/login", "/api/v2/me"]


def test_corrupt_export_fails_and_retains_partial_rehearsal_for_inspection(
    client, tmp_path, monkeypatch
):
    native = client.get

    def corrupted(path, *args, **kwargs):
        response = native(path, *args, **kwargs)
        if "/issued-exports/" in path and "/files/" in path:
            return httpx.Response(200, content=b"corrupt export", request=response.request)
        return response

    monkeypatch.setattr(client, "get", corrupted)
    output = tmp_path / "partial"
    output.mkdir()
    with pytest.raises(ValueError, match="checksum"):
        rehearse(client, output=output)
    assert json.loads((output / "session.json").read_text())["project_id"]
    assert (output / "application-import-metadata.json").is_file()
    assert (output / "issuance.json").is_file()
    assert not list(output.glob("issued-*"))


def test_specialist_artifact_names_cannot_escape_output_directory(client, tmp_path, monkeypatch):
    native = client.post

    def unsafe_file(path, *args, **kwargs):
        response = native(path, *args, **kwargs)
        if path.endswith("/vscorer-input"):
            data = response.json()
            data["files"] = {"../../unexpected.json": "{}"}
            return httpx.Response(200, json=data, request=response.request)
        return response

    monkeypatch.setattr(client, "post", unsafe_file)
    output = tmp_path / "safe"
    output.mkdir()
    with pytest.raises(ValueError, match="artifact filename"):
        rehearse(client, output=output)
    assert not (tmp_path / "unexpected.json").exists()
