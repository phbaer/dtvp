import importlib

from fastapi.testclient import TestClient

from test_setup import mock_tmrescore


def _parse_vector(vector: str) -> dict[str, str]:
    metrics: dict[str, str] = {}
    for part in vector.split("/"):
        if not part or part.startswith("CVSS:") or ":" not in part:
            continue
        key, value = part.split(":", 1)
        metrics[key] = value
    return metrics


def _build_test_client() -> TestClient:
    importlib.reload(mock_tmrescore)
    return TestClient(mock_tmrescore.app)


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
    assert vulnerability["original_score"] is not None
    assert vulnerability["original_vector"].startswith("CVSS:3.1/")
    assert vulnerability["original_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert vulnerability["rescored_score"] is not None
    assert vulnerability["rescored_score"] < vulnerability["original_score"]
    assert vulnerability["rescored_vector"].startswith("CVSS:3.1/")
    assert vulnerability["rescored_vector"] != vulnerability["original_vector"]

    original_metrics = _parse_vector(vulnerability["original_vector"])
    rescored_metrics = _parse_vector(vulnerability["rescored_vector"])
    for key in ("AV", "AC", "PR", "UI", "S", "C", "I", "A"):
        assert rescored_metrics[key] == original_metrics[key]
    assert any(key.startswith("M") for key in rescored_metrics)

    output_file = client.get(f"/api/v1/sessions/{session_id}/outputs/enriched-sbom.json")
    assert output_file.status_code == 200
    assert output_file.headers["content-type"].startswith("application/json")
    assert "vp:threatModelElementIds" in output_file.text