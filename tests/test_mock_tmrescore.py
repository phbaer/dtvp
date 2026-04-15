import importlib
import json
from pathlib import Path

from fastapi.testclient import TestClient

from test_setup import mock_tmrescore


def _build_test_client() -> TestClient:
    importlib.reload(mock_tmrescore)
    return TestClient(mock_tmrescore.app)


def _base_vector_components(vector: str) -> list[str]:
    return [part for part in vector.split('/') if not part.startswith('M')]


def test_mock_tmrescore_health_and_ui():
    client = _build_test_client()

    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["service"] == "mock-tmrescore"
    assert health.json()["ollama_configured"] is True

    ui = client.get("/ui")
    assert ui.status_code == 200
    assert "Mock TMRescore" in ui.text


def test_mock_tmrescore_inventory_flow_returns_downloadable_results():
    client = _build_test_client()

    create = client.post(
        "/api/v1/sessions",
        json={
            "application_name": "ExampleApp",
            "application_version": "multi-version:1.10.0",
        },
    )
    assert create.status_code == 201
    session_id = create.json()["session_id"]

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [
            {
                "bom-ref": "component-1",
                "type": "library",
                "name": "lib-a",
                "version": "1.0.0",
            }
        ],
        "vulnerabilities": [
            {
                "id": "CVE-2024-0001",
                "description": "Mock vulnerability",
                "ratings": [
                    {
                        "method": "CVSSv31",
                        "score": 8.8,
                        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    }
                ],
                "affects": [{"ref": "component-1"}],
            }
        ],
    }

    analyze = client.post(
        f"/api/v1/sessions/{session_id}/inventory",
        data={
            "chain_analysis": "true",
            "prioritize": "true",
            "what_if": "false",
            "enrich": "true",
            "ollama_model": "qwen2.5:14b",
        },
        files={
            "threatmodel": ("model.tm7", b"tm7", "application/octet-stream"),
            "sbom": ("sbom.json", importlib.import_module("json").dumps(sbom).encode("utf-8"), "application/json"),
        },
    )
    assert analyze.status_code == 200
    payload = analyze.json()
    assert payload["status"] == "completed"
    assert payload["total_cves"] == 1
    assert "rescored-report.json" in payload["outputs"]
    assert payload["llm_enrichment"] == {"enabled": True, "ollama_model": "qwen2.5:14b"}

    raw_results = client.get(f"/api/v1/sessions/{session_id}/results/json")
    assert raw_results.status_code == 200
    assert raw_results.json()["summary"]["vulnerability_count"] == 1
    assert raw_results.json()["summary"]["enrich"] is True
    assert raw_results.json()["summary"]["ollama_model"] == "qwen2.5:14b"
    vulnerability = raw_results.json()["vulnerabilities"][0]
    assert vulnerability["original_score"] == 8.8
    assert vulnerability["original_vector"].startswith("CVSS:3.1/")
    assert vulnerability["original_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert vulnerability["rescored_score"] is not None
    assert vulnerability["rescored_score"] < vulnerability["original_score"]
    assert vulnerability["rescored_vector"].startswith("CVSS:3.1/")
    assert vulnerability["rescored_vector"] != vulnerability["original_vector"]
    assert vulnerability["rescored_vector"].startswith("CVSS:3.")

    output_file = client.get(f"/api/v1/sessions/{session_id}/outputs/enriched-sbom.json")
    assert output_file.status_code == 200
    assert output_file.headers["content-type"].startswith("application/json")
    assert "vp:threatModelElementIds" in output_file.text


def test_mock_tmrescore_vex_results_include_detail_messages():
    client = _build_test_client()

    create = client.post(
        "/api/v1/sessions",
        json={
            "application_name": "ExampleApp",
            "application_version": "multi-version:1.10.0",
        },
    )
    assert create.status_code == 201
    session_id = create.json()["session_id"]

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [
            {
                "bom-ref": "component-1",
                "type": "library",
                "name": "lib-a",
                "version": "1.0.0",
            },
            {
                "bom-ref": "component-2",
                "type": "library",
                "name": "lib-b",
                "version": "2.0.0",
            },
        ],
        "vulnerabilities": [
            {
                "id": "CVE-2024-0001",
                "description": "Mock vulnerability one",
                "ratings": [
                    {
                        "method": "CVSSv31",
                        "score": 8.8,
                        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    }
                ],
                "affects": [{"ref": "component-1"}],
            },
            {
                "id": "CVE-2024-0002",
                "description": "Mock vulnerability two",
                "ratings": [
                    {
                        "method": "CVSSv31",
                        "score": 7.5,
                        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                    }
                ],
                "affects": [{"ref": "component-2"}],
            },
        ],
    }

    analyze = client.post(
        f"/api/v1/sessions/{session_id}/inventory",
        data={
            "chain_analysis": "true",
            "prioritize": "true",
            "what_if": "false",
            "enrich": "false",
        },
        files={
            "threatmodel": ("model.tm7", b"tm7", "application/octet-stream"),
            "sbom": ("sbom.json", importlib.import_module("json").dumps(sbom).encode("utf-8"), "application/json"),
        },
    )
    assert analyze.status_code == 200

    vex_results = client.get(f"/api/v1/sessions/{session_id}/results/vex")
    assert vex_results.status_code == 200
    vulnerabilities = vex_results.json()["vulnerabilities"]
    assert len(vulnerabilities) == 2

    first_analysis = vulnerabilities[0]["analysis"]
    second_analysis = vulnerabilities[1]["analysis"]

    assert first_analysis["detail"] == "Mock tmrescore result generated for local testing."
    assert first_analysis["response"][0]["detail"] == "Structured mock analysis response without a top-level detail message."

    assert second_analysis["detail"] == "Mock tmrescore result generated for local testing."
    assert second_analysis["response"][0]["detail"] == "Structured mock analysis response without a top-level detail message."


def test_mock_tmrescore_preserves_provided_vectors_without_rewriting_them():
    client = _build_test_client()

    create = client.post(
        "/api/v1/sessions",
        json={
            "application_name": "ExampleApp",
            "application_version": "1.0.0",
        },
    )
    assert create.status_code == 201
    session_id = create.json()["session_id"]

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [{"bom-ref": "component-1", "type": "library", "name": "lib-a", "version": "1.0.0"}],
        "vulnerabilities": [
            {
                "id": "CVE-2024-0001",
                "description": "Mock vulnerability",
                "ratings": [
                    {
                        "method": "CVSSv31",
                        "score": 8.8,
                        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    }
                ],
                "affects": [{"ref": "component-1"}],
            }
        ],
    }

    analyze = client.post(
        f"/api/v1/sessions/{session_id}/inventory",
        data={"chain_analysis": "true", "prioritize": "true", "what_if": "false", "enrich": "false"},
        files={
            "threatmodel": ("model.tm7", b"tm7", "application/octet-stream"),
            "sbom": ("sbom.json", importlib.import_module("json").dumps(sbom).encode("utf-8"), "application/json"),
        },
    )
    assert analyze.status_code == 200

    vulnerability = client.get(f"/api/v1/sessions/{session_id}/results/json").json()["vulnerabilities"][0]
    assert vulnerability["original_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert vulnerability["original_score"] == 8.8
    assert vulnerability["rescored_score"] is not None
    assert _base_vector_components(vulnerability["original_vector"]) == _base_vector_components(vulnerability["rescored_vector"])


def test_tmrescore_proposals_preserve_base_vector_components():
    proposals_path = Path(__file__).resolve().parents[1] / "data" / "tmrescore_proposals.json"
    proposals_data = json.loads(proposals_path.read_text())

    def base_vector_components(vector: str) -> list[str]:
        parts = vector.split('/')
        if parts[0].startswith('CVSS:'):
            parts = parts[1:]
        return [part for part in parts if not part.startswith('M')]

    for app_data in proposals_data.values():
        if not isinstance(app_data, dict):
            continue
        proposals = app_data.get('proposals', {})
        for proposal in proposals.values():
            original_vector = proposal.get('original_vector')
            rescored_vector = proposal.get('rescored_vector')
            if isinstance(original_vector, str) and isinstance(rescored_vector, str):
                assert base_vector_components(original_vector) == base_vector_components(rescored_vector), (
                    f"Proposal base components changed for {proposal.get('vuln_id', 'unknown')}"
                )
