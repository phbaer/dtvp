import json
import os
import importlib
from unittest.mock import AsyncMock, patch

import pytest
import httpx

from main import (
    app,
    get_current_user,
    load_tmrescore_project_cache,
    persist_tmrescore_project_snapshot,
    tmrescore_project_cache,
)
from test_setup import mock_tmrescore
from tmrescore_integration import build_analysis_sbom, build_tmrescore_proposals


@pytest.fixture(autouse=True)
def override_auth():
    app.dependency_overrides[get_current_user] = lambda: "testuser"
    yield
    app.dependency_overrides.pop(get_current_user, None)


def test_build_analysis_sbom_merged_versions_namespaces_components():
    analysis_inputs = [
        {
            "version": {"uuid": "proj-1", "version": "1.9.0"},
            "bom": {
                "metadata": {
                    "component": {
                        "bom-ref": "root-1",
                        "name": "ExampleApp",
                        "version": "1.9.0",
                        "type": "application",
                    }
                },
                "components": [
                    {
                        "bom-ref": "comp-a",
                        "uuid": "comp-a-uuid",
                        "name": "library-a",
                        "version": "1.0.0",
                    }
                ],
                "dependencies": [
                    {"ref": "root-1", "dependsOn": ["comp-a"]},
                ],
            },
            "vulnerabilities": [
                {
                    "component": {"uuid": "comp-a-uuid", "name": "library-a", "version": "1.0.0"},
                    "vulnerability": {
                        "vulnId": "CVE-2024-0001",
                        "severity": "HIGH",
                        "cvssV3BaseScore": 8.8,
                        "cvssV3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    },
                }
            ],
        },
        {
            "version": {"uuid": "proj-2", "version": "1.10.0"},
            "bom": {
                "metadata": {
                    "component": {
                        "bom-ref": "root-2",
                        "name": "ExampleApp",
                        "version": "1.10.0",
                        "type": "application",
                    }
                },
                "components": [
                    {
                        "bom-ref": "comp-b",
                        "uuid": "comp-b-uuid",
                        "name": "library-b",
                        "version": "2.0.0",
                    }
                ],
                "dependencies": [
                    {"ref": "root-2", "dependsOn": ["comp-b"]},
                ],
            },
            "vulnerabilities": [
                {
                    "component": {"uuid": "comp-b-uuid", "name": "library-b", "version": "2.0.0"},
                    "vulnerability": {
                        "vulnId": "CVE-2024-0001",
                        "severity": "CRITICAL",
                        "cvssV3BaseScore": 9.8,
                        "cvssV3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    },
                }
            ],
        },
    ]

    sbom = build_analysis_sbom(
        project_name="ExampleApp",
        analysis_inputs=analysis_inputs,
        scope="merged_versions",
        latest_version="1.10.0",
    )

    component_refs = {component["bom-ref"] for component in sbom["components"]}
    assert "urn:dtvp:tmrescore:ExampleApp:aggregate" in component_refs
    assert "urn:dtvp:tmrescore:proj-1:root" in component_refs
    assert "urn:dtvp:tmrescore:proj-2:root" in component_refs

    vulnerabilities = sbom["vulnerabilities"]
    assert len(vulnerabilities) == 1
    affects = {item["ref"] for item in vulnerabilities[0]["affects"]}
    assert any(ref.startswith("urn:dtvp:tmrescore:proj-1:component:") for ref in affects)
    assert any(ref.startswith("urn:dtvp:tmrescore:proj-2:component:") for ref in affects)

    source_versions = next(
        prop["value"]
        for prop in vulnerabilities[0]["properties"]
        if prop["name"] == "dtvp:sourceVersions"
    )
    assert source_versions == "1.9.0, 1.10.0"


def test_tmrescore_context_endpoint_uses_natural_version_order(client, mock_dt_client):
    mock_dt_client.get_projects.return_value = [
        {"name": "ExampleApp", "version": "1.9.0", "uuid": "proj-1"},
        {"name": "ExampleApp", "version": "1.10.0", "uuid": "proj-2"},
    ]

    response = client.get("/api/projects/ExampleApp/tmrescore/context")

    assert response.status_code == 200
    payload = response.json()
    assert payload["latest_version"] == "1.10.0"
    assert payload["recommended_scope"] == "merged_versions"
    assert payload["versions"] == ["1.9.0", "1.10.0"]
    assert payload["llm_enrichment"]["available"] is False
    assert payload["llm_enrichment"]["status"] == "integration_disabled"


def test_tmrescore_context_endpoint_uses_remote_health_for_ollama_availability(client, mock_dt_client):
    mock_dt_client.get_projects.return_value = [
        {"name": "ExampleApp", "version": "1.9.0", "uuid": "proj-1"},
        {"name": "ExampleApp", "version": "1.10.0", "uuid": "proj-2"},
    ]

    with patch.dict(
        os.environ,
        {
            "DTVP_TMRESCORE_URL": "http://tmrescore.local",
            "OLLAMA_HOST": "http://local-dtvp-host:11434",
        },
        clear=False,
    ):
        with patch(
            "main.TMRescoreClient.get_health",
            new=AsyncMock(return_value={"status": "ok", "ollama_configured": False}),
        ):
            response = client.get("/api/projects/ExampleApp/tmrescore/context")

    assert response.status_code == 200
    payload = response.json()
    assert payload["llm_enrichment"]["available"] is False
    assert payload["llm_enrichment"]["host_configured"] is False
    assert payload["llm_enrichment"]["status"] == "not_configured"
    assert (
        payload["llm_enrichment"]["warning"]
        == "LLM enrichment requires OLLAMA_HOST to be configured on the tmrescore backend."
    )


def test_tmrescore_context_endpoint_reports_remote_ollama_when_available(client, mock_dt_client):
    mock_dt_client.get_projects.return_value = [
        {"name": "ExampleApp", "version": "1.9.0", "uuid": "proj-1"},
        {"name": "ExampleApp", "version": "1.10.0", "uuid": "proj-2"},
    ]

    with patch.dict(os.environ, {"DTVP_TMRESCORE_URL": "http://tmrescore.local"}, clear=False):
        with patch(
            "main.TMRescoreClient.get_health",
            new=AsyncMock(return_value={"status": "ok", "ollama_configured": True}),
        ):
            response = client.get("/api/projects/ExampleApp/tmrescore/context")

    assert response.status_code == 200
    payload = response.json()
    assert payload["llm_enrichment"]["available"] is True
    assert payload["llm_enrichment"]["host_configured"] is True
    assert payload["llm_enrichment"]["status"] == "available"
    assert payload["llm_enrichment"]["warning"] is None


def test_tmrescore_context_endpoint_reports_unreachable_when_health_check_fails(client, mock_dt_client):
    mock_dt_client.get_projects.return_value = [
        {"name": "ExampleApp", "version": "1.9.0", "uuid": "proj-1"},
        {"name": "ExampleApp", "version": "1.10.0", "uuid": "proj-2"},
    ]

    with patch.dict(os.environ, {"DTVP_TMRESCORE_URL": "http://tmrescore.local"}, clear=False):
        with patch(
            "main.TMRescoreClient.get_health",
            new=AsyncMock(side_effect=httpx.ConnectError("health failed")),
        ):
            response = client.get("/api/projects/ExampleApp/tmrescore/context")

    assert response.status_code == 200
    payload = response.json()
    assert payload["llm_enrichment"]["available"] is False
    assert payload["llm_enrichment"]["host_configured"] is False
    assert payload["llm_enrichment"]["status"] == "unreachable"
    assert (
        payload["llm_enrichment"]["warning"]
        == "Could not verify LLM enrichment availability from the tmrescore backend."
    )


def test_tmrescore_project_cache_persists_to_disk(tmp_path):
    cache_file = tmp_path / "tmrescore-cache.json"
    snapshot = {
        "project_name": "ExampleApp",
        "session_id": "session-1",
        "scope": "merged_versions",
        "latest_version": "1.10.0",
        "analyzed_versions": ["1.9.0", "1.10.0"],
        "proposals": {
            "CVE-2024-0001": {
                "vuln_id": "CVE-2024-0001",
                "rescored_score": 8.0,
                "rescored_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MPR:L",
            }
        },
    }

    with patch.dict(os.environ, {"DTVP_TMRESCORE_CACHE_PATH": str(cache_file)}, clear=False):
        tmrescore_project_cache.clear()
        persist_tmrescore_project_snapshot("ExampleApp", snapshot)

        reloaded = load_tmrescore_project_cache()
        assert reloaded["ExampleApp"]["session_id"] == "session-1"
        assert reloaded["ExampleApp"]["proposals"]["CVE-2024-0001"]["rescored_score"] == 8.8

    tmrescore_project_cache.clear()


def test_tmrescore_project_cache_load_normalizes_scores_from_vectors(tmp_path):
    cache_file = tmp_path / "tmrescore-cache.json"
    cache_file.write_text(
        json.dumps(
            {
                "ExampleApp": {
                    "project_name": "ExampleApp",
                    "proposals": {
                        "CVE-2024-0001": {
                            "vuln_id": "CVE-2024-0001",
                            "original_score": 1.0,
                            "original_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "rescored_score": 1.0,
                            "rescored_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MPR:L",
                        }
                    },
                }
            }
        ),
        encoding="utf-8",
    )

    with patch.dict(os.environ, {"DTVP_TMRESCORE_CACHE_PATH": str(cache_file)}, clear=False):
        reloaded = load_tmrescore_project_cache()

    assert reloaded["ExampleApp"]["proposals"]["CVE-2024-0001"]["original_score"] == 9.8
    assert reloaded["ExampleApp"]["proposals"]["CVE-2024-0001"]["rescored_score"] == 8.8
    assert (
        reloaded["ExampleApp"]["proposals"]["CVE-2024-0001"]["rescored_vector"]
        == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MPR:L"
    )


def test_build_tmrescore_proposals_normalizes_scores_from_vectors():
    proposals = build_tmrescore_proposals(
        {
            "vulnerabilities": [
                {
                    "id": "CVE-2024-0001",
                    "original_score": 1.0,
                    "original_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "rescored_score": 1.0,
                    "rescored_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MPR:L",
                    "affected_refs": ["component-1"],
                }
            ]
        }
    )

    assert proposals["CVE-2024-0001"]["original_score"] == 9.8
    assert proposals["CVE-2024-0001"]["rescored_score"] == 8.8


def test_normalize_tmrescore_snapshot_upgrades_base_metric_rescore_to_modifier_rescore():
    reloaded = load_tmrescore_project_cache.__globals__["normalize_tmrescore_snapshot"](
        {
            "project_name": "ExampleApp",
            "proposals": {
                "CVE-2024-0001": {
                    "vuln_id": "CVE-2024-0001",
                    "original_vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N",
                    "rescored_vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N",
                }
            },
        }
    )

    proposal = reloaded["proposals"]["CVE-2024-0001"]
    assert proposal["rescored_vector"] == "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N/MPR:H"
    assert proposal["original_score"] == 3.3
    assert proposal["rescored_score"] == 2.9


def test_tmrescore_analyze_endpoint_builds_synthetic_sbom(client, mock_dt_client):
    mock_dt_client.get_projects.return_value = [
        {"name": "ExampleApp", "version": "1.0.0", "uuid": "proj-1"},
        {"name": "ExampleApp", "version": "1.1.0", "uuid": "proj-2"},
    ]
    mock_dt_client.get_vulnerabilities.side_effect = [
        [
            {
                "component": {"uuid": "component-1", "name": "lib-a", "version": "1.0.0"},
                "vulnerability": {"vulnId": "CVE-2024-0001", "severity": "HIGH", "cvssV3BaseScore": 8.2},
            }
        ],
        [
            {
                "component": {"uuid": "component-2", "name": "lib-b", "version": "2.0.0"},
                "vulnerability": {"vulnId": "CVE-2024-0002", "severity": "MEDIUM", "cvssV3BaseScore": 5.0},
            }
        ],
    ]
    mock_dt_client.get_project_vulnerabilities.side_effect = [
        [{"vulnId": "CVE-2024-0001", "cvssV3BaseScore": 8.2}],
        [{"vulnId": "CVE-2024-0002", "cvssV3BaseScore": 5.0}],
    ]
    mock_dt_client.get_bom.side_effect = [
        {
            "metadata": {"component": {"bom-ref": "root-1", "name": "ExampleApp", "version": "1.0.0", "type": "application"}},
            "components": [{"bom-ref": "comp-1", "uuid": "component-1", "name": "lib-a", "version": "1.0.0"}],
            "dependencies": [{"ref": "root-1", "dependsOn": ["comp-1"]}],
        },
        {
            "metadata": {"component": {"bom-ref": "root-2", "name": "ExampleApp", "version": "1.1.0", "type": "application"}},
            "components": [{"bom-ref": "comp-2", "uuid": "component-2", "name": "lib-b", "version": "2.0.0"}],
            "dependencies": [{"ref": "root-2", "dependsOn": ["comp-2"]}],
        },
    ]

    analyze_mock = AsyncMock(
        return_value={
            "session_id": "session-1",
            "status": "completed",
            "total_cves": 2,
            "rescored_count": 2,
            "avg_score_reduction": 1.25,
            "elapsed_seconds": 4.2,
            "outputs": {"rescored-report.json": True},
        }
    )

    with patch.dict(os.environ, {"DTVP_TMRESCORE_URL": "http://tmrescore.local", "OLLAMA_HOST": "http://ollama.local:11434"}):
        with patch("main.TMRescoreClient.create_session", new=AsyncMock(return_value={"session_id": "session-1"})):
            with patch("main.TMRescoreClient.analyze_inventory", new=analyze_mock):
                response = client.post(
                    "/api/projects/ExampleApp/tmrescore/analyze",
                    data={
                        "scope": "merged_versions",
                        "enrich": "true",
                        "ollama_model": "llama3.1:8b",
                    },
                    files={"threatmodel": ("model.tm7", b"tm7-data", "application/octet-stream")},
                )

    assert response.status_code == 200
    payload = response.json()
    assert payload["scope"] == "merged_versions"
    assert payload["analyzed_versions"] == ["1.0.0", "1.1.0"]
    assert payload["sbom_component_count"] >= 3
    assert payload["sbom_vulnerability_count"] == 2
    assert payload["download_urls"]["json"].endswith("/api/tmrescore/sessions/session-1/results/json")
    assert payload["llm_enrichment"] == {"enabled": True, "ollama_model": "llama3.1:8b"}
    assert analyze_mock.await_args.kwargs["enrich"] is True
    assert analyze_mock.await_args.kwargs["ollama_model"] == "llama3.1:8b"


def test_tmrescore_backend_api_end_to_end_against_mock_service(client, mock_dt_client):
    importlib.reload(mock_tmrescore)
    real_async_client = httpx.AsyncClient

    mock_dt_client.get_projects.return_value = [
        {"name": "ExampleApp", "version": "1.9.0", "uuid": "proj-1"},
        {"name": "ExampleApp", "version": "1.10.0", "uuid": "proj-2"},
    ]
    mock_dt_client.get_vulnerabilities.side_effect = [
        [
            {
                "component": {"uuid": "component-1", "name": "lib-a", "version": "1.0.0"},
                "vulnerability": {
                    "vulnId": "CVE-2024-0001",
                    "severity": "HIGH",
                    "cvssV3BaseScore": 8.8,
                    "cvssV3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                },
            }
        ],
        [
            {
                "component": {"uuid": "component-2", "name": "lib-b", "version": "2.0.0"},
                "vulnerability": {
                    "vulnId": "CVE-2024-0002",
                    "severity": "MEDIUM",
                    "cvssV3BaseScore": 5.4,
                    "cvssV3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                },
            }
        ],
    ]
    mock_dt_client.get_project_vulnerabilities.side_effect = [
        [{"vulnId": "CVE-2024-0001", "cvssV3BaseScore": 8.8, "cvssV3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        [{"vulnId": "CVE-2024-0002", "cvssV3BaseScore": 5.4, "cvssV3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"}],
    ]
    mock_dt_client.get_bom.side_effect = [
        {
            "metadata": {"component": {"bom-ref": "root-1", "name": "ExampleApp", "version": "1.9.0", "type": "application"}},
            "components": [{"bom-ref": "comp-1", "uuid": "component-1", "name": "lib-a", "version": "1.0.0"}],
            "dependencies": [{"ref": "root-1", "dependsOn": ["comp-1"]}],
        },
        {
            "metadata": {"component": {"bom-ref": "root-2", "name": "ExampleApp", "version": "1.10.0", "type": "application"}},
            "components": [{"bom-ref": "comp-2", "uuid": "component-2", "name": "lib-b", "version": "2.0.0"}],
            "dependencies": [{"ref": "root-2", "dependsOn": ["comp-2"]}],
        },
    ]

    def build_mock_async_client(*args, **kwargs):
        timeout = kwargs.get("timeout")
        return real_async_client(
            transport=httpx.ASGITransport(app=mock_tmrescore.app),
            base_url="http://mock-tmrescore.test",
            timeout=timeout,
        )

    with patch.dict(os.environ, {"DTVP_TMRESCORE_URL": "http://mock-tmrescore.test"}):
        with patch("tmrescore_integration.httpx.AsyncClient", side_effect=build_mock_async_client):
            response = client.post(
                "/api/projects/ExampleApp/tmrescore/analyze",
                data={"scope": "merged_versions", "chain_analysis": "true", "prioritize": "true"},
                files={"threatmodel": ("model.tm7", b"tm7-data", "application/octet-stream")},
            )

            assert response.status_code == 200
            payload = response.json()
            assert payload["status"] == "completed"
            assert payload["scope"] == "merged_versions"
            assert payload["analyzed_versions"] == ["1.9.0", "1.10.0"]
            session_id = payload["session_id"]

            results_json = client.get(f"/api/tmrescore/sessions/{session_id}/results/json")
            assert results_json.status_code == 200
            results_payload = results_json.json()
            assert results_payload["summary"]["vulnerability_count"] == 2

            cached_proposals = client.get("/api/projects/ExampleApp/tmrescore/proposals")
            assert cached_proposals.status_code == 200
            proposals_payload = cached_proposals.json()
            assert proposals_payload["project_name"] == "ExampleApp"
            assert proposals_payload["scope"] == "merged_versions"
            proposal_one = proposals_payload["proposals"]["CVE-2024-0001"]
            proposal_two = proposals_payload["proposals"]["CVE-2024-0002"]
            assert proposal_one["original_score"] is not None
            assert proposal_one["rescored_score"] is not None
            assert proposal_one["rescored_score"] < proposal_one["original_score"]
            assert proposal_one["original_vector"].startswith("CVSS:3.1/")
            assert proposal_one["rescored_vector"].startswith("CVSS:3.1/")
            assert proposal_one["rescored_vector"] != proposal_one["original_vector"]
            assert proposal_one["rescored_vector"].startswith(f"{proposal_one['original_vector']}/")
            assert "/M" in proposal_one["rescored_vector"]
            assert proposal_two["rescored_vector"].startswith("CVSS:3.1/")
            assert proposal_two["original_vector"].startswith("CVSS:3.1/")
            assert proposal_two["rescored_vector"] != proposal_two["original_vector"]
            assert proposal_two["rescored_vector"].startswith(f"{proposal_two['original_vector']}/")
            assert "/M" in proposal_two["rescored_vector"]

            vex = client.get(f"/api/tmrescore/sessions/{session_id}/results/vex")
            assert vex.status_code == 200
            assert len(vex.json()["vulnerabilities"]) == 2

            enriched_sbom = client.get(
                f"/api/tmrescore/sessions/{session_id}/outputs/enriched-sbom.json"
            )
            assert enriched_sbom.status_code == 200
            assert "vp:threatModelElementIds" in enriched_sbom.text