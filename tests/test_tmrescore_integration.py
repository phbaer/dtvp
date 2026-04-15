import json
import os
import importlib
import time
from unittest.mock import AsyncMock, patch

import pytest
import httpx
import main as main_module

from main import (
    app,
    get_current_user,
    load_tmrescore_project_cache,
    prune_tmrescore_analysis_tasks,
    persist_tmrescore_project_snapshot,
)
from test_setup import mock_tmrescore
from tmrescore_integration import (
    build_analysis_sbom,
    build_dtvp_vulnerability_proposals,
    build_tmrescore_proposals,
    get_tmrescore_generated_at,
    is_meaningful_tmrescore_proposal,
)


@pytest.fixture(autouse=True)
def override_auth():
    app.dependency_overrides[get_current_user] = lambda: "testuser"
    yield
    app.dependency_overrides.pop(get_current_user, None)
    main_module.tmrescore_analysis_tasks.clear()


def wait_for_tmrescore_progress(client, session_id: str, *, expected_status: str = "completed"):
    last_payload = None
    for _ in range(60):
        response = client.get(f"/api/tmrescore/sessions/{session_id}/progress")
        assert response.status_code == 200
        last_payload = response.json()
        if last_payload["status"] == expected_status:
            return last_payload
        time.sleep(0.05)
    pytest.fail(f"Timed out waiting for tmrescore session {session_id} to reach {expected_status}: {last_payload}")


def test_prune_tmrescore_analysis_tasks_removes_expired_terminal_entries():
    main_module.tmrescore_analysis_tasks.clear()
    main_module.tmrescore_analysis_tasks["expired"] = {
        "session_id": "expired",
        "status": "completed",
        "completed_at": 10.0,
        "updated_at": 10.0,
    }
    main_module.tmrescore_analysis_tasks["fresh"] = {
        "session_id": "fresh",
        "status": "completed",
        "completed_at": 3500.0,
        "updated_at": 3500.0,
    }
    main_module.tmrescore_analysis_tasks["running"] = {
        "session_id": "running",
        "status": "running",
        "updated_at": 10.0,
    }

    with patch.dict(os.environ, {"DTVP_TMRESCORE_TASK_TTL_SECONDS": "3600"}, clear=False):
        prune_tmrescore_analysis_tasks(now=4000.0)

    assert "expired" not in main_module.tmrescore_analysis_tasks
    assert "fresh" in main_module.tmrescore_analysis_tasks
    assert "running" in main_module.tmrescore_analysis_tasks


def test_tmrescore_project_state_returns_latest_cached_task(client):
    main_module.tmrescore_analysis_tasks.clear()
    main_module.tmrescore_analysis_tasks["session-older"] = {
        "session_id": "session-older",
        "project_name": "ExampleApp",
        "scope": "merged_versions",
        "latest_version": "1.9.0",
        "analyzed_versions": ["1.9.0"],
        "llm_enrichment": {"enabled": False, "ollama_model": None},
        "status": "completed",
        "progress": 100,
        "message": "TMRescore analysis completed.",
        "log": ["TMRescore analysis completed."],
        "result": {"session_id": "session-older", "status": "completed"},
        "created_at": 100.0,
        "updated_at": 100.0,
        "completed_at": 100.0,
    }
    main_module.tmrescore_analysis_tasks["session-latest"] = {
        "session_id": "session-latest",
        "project_name": "ExampleApp",
        "scope": "latest_only",
        "latest_version": "1.10.0",
        "analyzed_versions": ["1.10.0"],
        "llm_enrichment": {"enabled": True, "ollama_model": "llama3.1:8b"},
        "status": "running",
        "progress": 64,
        "message": "Rescoring vulnerabilities against the threat model...",
        "log": ["Queued tmrescore analysis.", "Rescoring vulnerabilities against the threat model..."],
        "result": None,
        "created_at": 200.0,
        "updated_at": 250.0,
        "completed_at": None,
    }

    response = client.get("/api/projects/ExampleApp/tmrescore/state")

    assert response.status_code == 200
    payload = response.json()
    assert payload["session_id"] == "session-latest"
    assert payload["scope"] == "latest_only"
    assert payload["status"] == "running"
    assert payload["progress"] == 64
    assert payload["created_at"] == 200.0
    assert payload["updated_at"] == 250.0
    assert payload["completed_at"] is None
    assert payload["result"] is None


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


def test_tmrescore_sbom_download_endpoint_returns_synthetic_analysis_sbom(client, mock_dt_client):
    mock_dt_client.get_projects.return_value = [
        {"name": "ExampleApp", "version": "1.9.0", "uuid": "proj-1"},
        {"name": "ExampleApp", "version": "1.10.0", "uuid": "proj-2"},
    ]
    mock_dt_client.get_vulnerabilities.side_effect = [[], []]
    mock_dt_client.get_project_vulnerabilities.side_effect = [[], []]
    mock_dt_client.get_bom.side_effect = [
        {
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
                    "bom-ref": "component-a",
                    "uuid": "component-a-uuid",
                    "name": "library-a",
                    "version": "1.0.0",
                }
            ],
        },
        {
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
                    "bom-ref": "component-b",
                    "uuid": "component-b-uuid",
                    "name": "library-b",
                    "version": "2.0.0",
                }
            ],
        },
    ]

    response = client.get("/api/projects/ExampleApp/tmrescore/sbom", params={"scope": "merged_versions"})

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert "attachment; filename=\"ExampleApp-merged_versions-1.10.0-analysis-sbom.cyclonedx.json\"" in response.headers["content-disposition"]

    payload = response.json()
    component_refs = {component["bom-ref"] for component in payload["components"]}
    assert "urn:dtvp:tmrescore:ExampleApp:aggregate" in component_refs
    assert "urn:dtvp:tmrescore:proj-1:root" in component_refs
    assert "urn:dtvp:tmrescore:proj-2:root" in component_refs


def test_tmrescore_sbom_summary_endpoint_returns_preflight_counts(client, mock_dt_client):
    mock_dt_client.get_projects.return_value = [
        {"name": "ExampleApp", "version": "1.9.0", "uuid": "proj-1"},
        {"name": "ExampleApp", "version": "1.10.0", "uuid": "proj-2"},
    ]
    mock_dt_client.get_vulnerabilities.side_effect = [
        [
            {
                "component": {"uuid": "component-a-uuid", "name": "library-a", "version": "1.0.0"},
                "vulnerability": {"vulnId": "CVE-2024-0001", "severity": "HIGH"},
            }
        ],
        [],
    ]
    mock_dt_client.get_project_vulnerabilities.side_effect = [
        [{"vulnId": "CVE-2024-0001", "cvssV3BaseScore": 8.8, "cvssV3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        [],
    ]
    mock_dt_client.get_bom.side_effect = [
        {
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
                    "bom-ref": "component-a",
                    "uuid": "component-a-uuid",
                    "name": "library-a",
                    "version": "1.0.0",
                }
            ],
        },
        {
            "metadata": {
                "component": {
                    "bom-ref": "root-2",
                    "name": "ExampleApp",
                    "version": "1.10.0",
                    "type": "application",
                }
            },
            "components": [],
        },
    ]

    response = client.get("/api/projects/ExampleApp/tmrescore/sbom/summary", params={"scope": "merged_versions"})

    assert response.status_code == 200
    payload = response.json()
    assert payload["scope"] == "merged_versions"
    assert payload["latest_version"] == "1.10.0"
    assert payload["analyzed_versions"] == ["1.9.0", "1.10.0"]
    assert payload["component_count"] >= 3
    assert payload["vulnerability_count"] == 1


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
        main_module.tmrescore_project_cache.clear()
        persist_tmrescore_project_snapshot("ExampleApp", snapshot)

        reloaded = load_tmrescore_project_cache()
        assert reloaded["ExampleApp"]["session_id"] == "session-1"
        assert reloaded["ExampleApp"]["proposals"]["CVE-2024-0001"]["rescored_score"] == 8.0

    main_module.tmrescore_project_cache.clear()


def test_tmrescore_project_cache_load_preserves_provided_scores(tmp_path):
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

    assert reloaded["ExampleApp"]["proposals"]["CVE-2024-0001"]["original_score"] == 1.0
    assert reloaded["ExampleApp"]["proposals"]["CVE-2024-0001"]["rescored_score"] == 1.0
    assert (
        reloaded["ExampleApp"]["proposals"]["CVE-2024-0001"]["rescored_vector"]
        == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MPR:L"
    )


def test_build_tmrescore_proposals_preserves_provided_scores():
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

    assert proposals["CVE-2024-0001"]["original_score"] == 1.0
    assert proposals["CVE-2024-0001"]["rescored_score"] == 1.0


def test_build_tmrescore_proposals_extracts_rescore_from_vex_document():
    proposals = build_tmrescore_proposals(
        {
            "metadata": {"timestamp": "2026-03-30T00:00:00Z"},
            "vulnerabilities": [
                {
                    "id": "CVE-2024-0001",
                    "analysis": {
                        "state": "in_triage",
                        "detail": "Threat model found compensating controls.",
                        "response": [
                            {
                                "title": "LLM enrichment",
                                "detail": "Threat justification enriched for the service boundary.",
                            }
                        ],
                    },
                    "ratings": [
                        {
                            "source": {"name": "NVD"},
                            "method": "CVSSv31",
                            "score": 9.8,
                            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        },
                        {
                            "source": {"name": "CVSS Re-Scorer (Environmental)"},
                            "method": "CVSSv31",
                            "score": 8.8,
                            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MPR:L",
                        }
                    ],
                    "properties": [
                        {"name": "cvss-rescorer:original_severity", "value": "CRITICAL"},
                        {"name": "cvss-rescorer:rescored_severity", "value": "HIGH"},
                        {"name": "cvss-rescorer:cwe_descriptions", "value": "{\"CWE-79\": \"XSS\"}"},
                        {"name": "cvss-rescorer:evaluations", "value": "[{\"element\": \"web\", \"vector\": \"CVSS:3.1/.../MPR:L\"}]"},
                    ],
                    "affects": [{"ref": "component-1"}],
                }
            ],
        }
    )

    assert proposals["CVE-2024-0001"]["description"] == "Threat model found compensating controls."
    assert proposals["CVE-2024-0001"]["details"] == "Threat model found compensating controls."
    assert proposals["CVE-2024-0001"]["analysis"] == {
        "state": "in_triage",
        "detail": "Threat model found compensating controls.",
        "response": [
            {
                "title": "LLM enrichment",
                "detail": "Threat justification enriched for the service boundary.",
            }
        ],
    }
    assert proposals["CVE-2024-0001"]["rescored_score"] == 8.8
    assert proposals["CVE-2024-0001"]["rescored_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MPR:L"
    assert proposals["CVE-2024-0001"]["affected_refs"] == ["component-1"]
    assert proposals["CVE-2024-0001"]["original_score"] is None
    assert proposals["CVE-2024-0001"]["original_severity"] == "CRITICAL"
    assert proposals["CVE-2024-0001"]["rescored_severity"] == "HIGH"
    assert proposals["CVE-2024-0001"]["cwe_descriptions"] == {"CWE-79": "XSS"}
    assert proposals["CVE-2024-0001"]["evaluations"] == [{"element": "web", "vector": "CVSS:3.1/.../MPR:L"}]
    assert get_tmrescore_generated_at({"metadata": {"timestamp": "2026-03-30T00:00:00Z"}}) == "2026-03-30T00:00:00Z"


def test_build_tmrescore_proposals_ignores_vex_entries_without_rescored_vector():
    proposals = build_tmrescore_proposals(
        {
            "vulnerabilities": [
                {
                    "id": "CVE-2024-0002",
                    "ratings": [{"source": {"name": "CVSS Re-Scorer (Environmental)"}, "method": "CVSSv31", "score": 7.1}],
                    "properties": [
                        {"name": "cvss-rescorer:original_severity", "value": "HIGH"},
                        {"name": "cvss-rescorer:rescored_severity", "value": "MEDIUM"},
                    ],
                }
            ]
        }
    )

    assert proposals == {}


def test_build_tmrescore_proposals_ignores_non_rescorer_ratings():
    proposals = build_tmrescore_proposals(
        {
            "vulnerabilities": [
                {
                    "id": "CVE-2024-0003",
                    "analysis": {"detail": "This should not produce a proposal without an environmental rescoring rating."},
                    "ratings": [
                        {
                            "source": {"name": "NVD"},
                            "method": "CVSSv31",
                            "score": 9.1,
                            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        }
                    ],
                }
            ]
        }
    )

    assert proposals == {}


def test_is_meaningful_tmrescore_proposal_requires_actual_change():
    assert is_meaningful_tmrescore_proposal(
        {
            "original_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "rescored_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MPR:L",
        }
    ) is True
    assert is_meaningful_tmrescore_proposal(
        {
            "original_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "rescored_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }
    ) is False
    assert is_meaningful_tmrescore_proposal(
        {
            "original_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "rescored_vector": "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }
    ) is True


def test_build_dtvp_vulnerability_proposals_extracts_original_scores_from_loaded_findings():
    proposals = build_dtvp_vulnerability_proposals(
        [
            {
                "vulnerabilities": [
                    {
                        "vulnerability": {
                            "vulnId": "CVE-2024-0001",
                            "cvssV3BaseScore": 9.8,
                            "cvssV3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        }
                    }
                ]
            }
        ]
    )

    assert proposals["CVE-2024-0001"]["original_score"] == 9.8
    assert proposals["CVE-2024-0001"]["original_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert proposals["CVE-2024-0001"]["rescored_score"] is None


def test_normalize_tmrescore_snapshot_preserves_provided_vectors():
    reloaded = load_tmrescore_project_cache.__globals__["normalize_tmrescore_snapshot"](
        {
            "project_name": "ExampleApp",
            "proposals": {
                "CVE-2024-0001": {
                    "vuln_id": "CVE-2024-0001",
                    "original_vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N",
                    "rescored_vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N/MPR:H",
                }
            },
        }
    )

    proposal = reloaded["proposals"]["CVE-2024-0001"]
    assert proposal["rescored_vector"] == "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N/MPR:H"
    assert proposal["original_score"] is None
    assert proposal["rescored_score"] is None


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
                with patch(
                    "main.TMRescoreClient.get_results_vex",
                    new=AsyncMock(return_value={"metadata": {"timestamp": "2026-03-30T00:00:00Z"}, "vulnerabilities": []}),
                ):
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
                    assert payload["status"] == "running"
                    assert payload["session_id"] == "session-1"

                    progress_payload = wait_for_tmrescore_progress(client, "session-1")
                    assert progress_payload["result"] is None
                    results_response = client.get("/api/tmrescore/sessions/session-1/results")
                    assert results_response.status_code == 200
                    final_result = results_response.json()
                    assert final_result["scope"] == "merged_versions"
                    assert final_result["analyzed_versions"] == ["1.0.0", "1.1.0"]
                    assert final_result["sbom_component_count"] >= 3
                    assert final_result["sbom_vulnerability_count"] == 2
                    assert final_result["download_urls"]["json"].endswith("/api/tmrescore/sessions/session-1/results/json")
                    assert final_result["llm_enrichment"] == {"enabled": True, "ollama_model": "llama3.1:8b"}

    assert analyze_mock.await_args.kwargs["enrich"] is True
    assert analyze_mock.await_args.kwargs["ollama_model"] == "llama3.1:8b"


def test_tmrescore_analyze_endpoint_polls_progress_after_gateway_timeout(client, mock_dt_client):
    mock_dt_client.get_projects.return_value = [
        {"name": "ExampleApp", "version": "1.0.0", "uuid": "proj-1"},
    ]
    mock_dt_client.get_vulnerabilities.return_value = []
    mock_dt_client.get_project_vulnerabilities.return_value = []
    mock_dt_client.get_bom.return_value = {
        "metadata": {"component": {"bom-ref": "root-1", "name": "ExampleApp", "version": "1.0.0", "type": "application"}},
        "components": [],
        "dependencies": [],
        "vulnerabilities": [],
    }

    request = httpx.Request("POST", "http://tmrescore.local/api/v1/sessions/session-1/inventory")
    timeout_error = httpx.HTTPStatusError(
        "gateway timeout",
        request=request,
        response=httpx.Response(504, request=request),
    )

    with patch.dict(os.environ, {"DTVP_TMRESCORE_URL": "http://tmrescore.local"}):
        with patch("main.TMRescoreClient.create_session", new=AsyncMock(return_value={"session_id": "session-1"})):
            with patch("main.TMRescoreClient.analyze_inventory", new=AsyncMock(side_effect=timeout_error)):
                with patch(
                    "main.TMRescoreClient.get_progress",
                    new=AsyncMock(side_effect=[
                        {"session_id": "session-1", "status": "running", "progress": 80},
                        {"session_id": "session-1", "status": "completed", "progress": 100},
                    ]),
                ) as get_progress_mock:
                    with patch(
                        "main.TMRescoreClient.get_results",
                        new=AsyncMock(return_value={
                            "session_id": "session-1",
                            "status": "completed",
                            "total_cves": 0,
                            "rescored_count": 0,
                            "avg_score_reduction": 0.0,
                            "elapsed_seconds": 12.0,
                            "outputs": {},
                        }),
                    ):
                        with patch(
                            "main.TMRescoreClient.get_results_vex",
                            new=AsyncMock(return_value={"metadata": {"timestamp": "2026-03-30T00:00:00Z"}, "vulnerabilities": []}),
                        ):
                            response = client.post(
                                "/api/projects/ExampleApp/tmrescore/analyze",
                                files={"threatmodel": ("model.tm7", b"tm7-data", "application/octet-stream")},
                            )

                            assert response.status_code == 200
                            payload = response.json()
                            assert payload["status"] == "running"
                            progress_payload = wait_for_tmrescore_progress(client, "session-1")
                            assert progress_payload["status"] == "completed"
                            assert progress_payload["result"] is None
                            results_response = client.get("/api/tmrescore/sessions/session-1/results")
                            assert results_response.status_code == 200
                            assert results_response.json()["session_id"] == "session-1"

    assert get_progress_mock.await_count >= 2


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
            assert payload["status"] == "running"
            session_id = payload["session_id"]

            progress_payload = wait_for_tmrescore_progress(client, session_id)
            assert progress_payload["result"] is None
            results_response = client.get(f"/api/tmrescore/sessions/{session_id}/results")
            assert results_response.status_code == 200
            final_result = results_response.json()
            assert final_result["status"] == "completed"
            assert final_result["scope"] == "merged_versions"
            assert final_result["analyzed_versions"] == ["1.9.0", "1.10.0"]

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
            assert proposal_one["rescored_vector"] != proposal_one["original_vector"]
            assert proposal_two["rescored_vector"].startswith("CVSS:3.1/")
            assert proposal_two["original_vector"].startswith("CVSS:3.1/")
            assert proposal_two["rescored_vector"] != proposal_two["original_vector"]
            assert proposal_two["rescored_vector"] != proposal_two["original_vector"]

            vex = client.get(f"/api/tmrescore/sessions/{session_id}/results/vex")
            assert vex.status_code == 200
            assert len(vex.json()["vulnerabilities"]) == 2

            enriched_sbom = client.get(
                f"/api/tmrescore/sessions/{session_id}/outputs/enriched-sbom.json"
            )
            assert enriched_sbom.status_code == 200
            assert "vp:threatModelElementIds" in enriched_sbom.text