import asyncio
import copy
import json

import httpx
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from src.api.jobs import Job
from src.api.jobs import apply_progress_event as _apply_progress_event
from src.api.jobs import job_status_response as _job_status_response
from src.api.models import (
    AnalysisJustification,
    AnalysisResponse,
    AnalysisState,
    Assessment,
    AssessRequest,
    AssessResponse,
    JobStatus,
)
from src.llm import prompt_registry
from src.llm.openwebui_client import OpenWebUIClient
from src.main import (
    app,
)
from src.security import validate_focus_path, validate_service_auth_configuration


SERVICE_HEADERS = {
    "Authorization": "Bearer test-only-agentyzer-service-token-1234567890",
    "X-Agentyzer-Owner": "test-owner",
}
ADMIN_HEADERS = {
    "Authorization": "Bearer test-only-agentyzer-admin-token-123456789012",
    "X-Agentyzer-Owner": "*",
}


@pytest.fixture(scope="module")
def client():
    with TestClient(app, headers=SERVICE_HEADERS) as c:
        yield c


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json().get("status") == "ok"


def test_service_authentication_is_required(client):
    response = client.get(
        "/health",
        headers={"Authorization": "Bearer invalid"},
    )

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert (
        client.get(
            "/openapi.json",
            headers={"Authorization": "Bearer invalid"},
        ).status_code
        == 401
    )


def test_production_service_auth_configuration_fails_closed(monkeypatch):
    monkeypatch.setenv("AGENTYZER_ENVIRONMENT", "production")
    monkeypatch.delenv("AGENTYZER_SERVICE_TOKEN", raising=False)
    monkeypatch.delenv("AGENTYZER_SERVICE_TOKEN_FILE", raising=False)
    monkeypatch.delenv("AGENTYZER_ALLOW_UNAUTHENTICATED", raising=False)

    with pytest.raises(RuntimeError, match="AGENTYZER_SERVICE_TOKEN"):
        validate_service_auth_configuration()


def test_admin_service_token_must_be_distinct(monkeypatch):
    token = "test-only-shared-agentyzer-token-1234567890"
    monkeypatch.setenv("AGENTYZER_ENVIRONMENT", "production")
    monkeypatch.setenv("AGENTYZER_SERVICE_TOKEN", token)
    monkeypatch.setenv("AGENTYZER_ADMIN_TOKEN", token)

    with pytest.raises(RuntimeError, match="must differ"):
        validate_service_auth_configuration()


def test_production_focus_path_is_confined_to_repository_root(
    monkeypatch,
    tmp_path,
):
    repo_root = tmp_path / "repos"
    checkout = repo_root / "project"
    checkout.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    monkeypatch.setenv("AGENTYZER_ENVIRONMENT", "production")
    monkeypatch.setenv("AGENTYZER_REPOS_DIR", str(repo_root))
    monkeypatch.delenv("AGENTYZER_ALLOW_EXTERNAL_FOCUS_PATH", raising=False)

    assert validate_focus_path(str(checkout)) == str(checkout.resolve())
    with pytest.raises(HTTPException, match="repository root"):
        validate_focus_path(str(outside))


def test_health_exposes_service_configuration_and_backend(client):
    r = client.get("/health")
    assert r.status_code == 200
    data = r.json()

    configuration = data["configuration"]
    assert configuration["service_name"] == "Agentic Vulnerability Analyzer"
    assert configuration["service_version"] == "0.1.0"
    assert configuration["features"]["async_assessments"] is True
    assert configuration["features"]["request_model_override"] is True

    repositories = configuration["repositories"]
    assert repositories["workspace_dir"]
    assert isinstance(repositories["component_count"], int)
    assert isinstance(repositories["components"], list)

    backend = data["backend"]
    assert backend["llm"]["model"] == data["model"]
    assert backend["jobs"]["job_store"] == "sqlite"
    assert backend["jobs"]["max_concurrent_jobs"] >= 1
    assert backend["jobs"]["available_slots"] >= 0
    assert "running" in backend["jobs"]["status_counts"]
    assert "AGENTYZER_MAX_CONCURRENT_JOBS" in backend["repositories"]["parallel_safety"]

    config_r = client.get("/configuration")
    assert config_r.status_code == 200
    assert config_r.json()["configuration"] == configuration


def test_prompt_inspection_endpoint_is_opt_in_for_values(client):
    metadata_r = client.get("/prompts")
    assert metadata_r.status_code == 200
    metadata = metadata_r.json()
    assert metadata["schema_version"] == "agentyzer.prompts/v1"
    assert metadata["include_values"] is False
    assert metadata["bundles"]
    assert "values" not in metadata["bundles"][0]

    values_r = client.get(
        "/prompts",
        params={"include_values": "true", "system_only": "true"},
    )
    assert values_r.status_code == 200
    values = values_r.json()
    verdict = next(bundle for bundle in values["bundles"] if bundle["bundle"] == "verdict")
    assert "system" in verdict["values"]
    assert "few_shot" not in verdict["values"]


def test_jobs_list_uses_envelope_metadata(client):
    r = client.post(
        "/assess",
        json={"vuln_id": "CVE-0000-0000", "component_name": "unknown-component"},
    )
    assert r.status_code == 200
    job_id = r.json()["job_id"]

    jobs_r = client.get("/jobs")
    assert jobs_r.status_code == 200
    data = jobs_r.json()

    assert data["configuration"]["service_name"] == "Agentic Vulnerability Analyzer"
    assert data["backend"]["jobs"]["max_concurrent_jobs"] >= 1
    listed = [job for job in data["jobs"] if job["job_id"] == job_id]
    assert listed
    assert job_id in app.state.job_store.load()
    assert "configuration" not in listed[0] or listed[0]["configuration"] is None
    assert "backend" not in listed[0] or listed[0]["backend"] is None

    client.delete(f"/jobs/{job_id}")
    assert job_id not in app.state.job_store.load()


def _seed_completed_parent_job(job_id: str = "parent-follow-up") -> Job:
    job = Job(
        job_id,
        AssessRequest(
            vuln_id="CVE-2026-FOLLOW",
            component_name="keycloak-extension",
        ),
        owner="test-owner",
    )
    job.status = JobStatus.completed
    job.finished_at = "2026-07-06T10:00:00+00:00"
    job.result = AssessResponse(
        assessment=Assessment(
            affected=False,
            verdict="Not Affected",
            confidence="Medium",
            exposure="transitive",
            summary="Extension is not affected.",
            reasoning="Only extension-specific code was checked.",
            analysis=AnalysisState.NOT_AFFECTED,
            justification=AnalysisJustification.CODE_NOT_REACHABLE,
            response=AnalysisResponse.NOT_SET,
            details="No extension entry point reaches the vulnerable API.",
            cvss_vector=None,
            cvss_score=None,
        ),
        steps=[],
    )
    app.state.jobs[job.id] = job
    return job


def test_jobs_are_isolated_by_caller_owner(client):
    alice = Job(
        "owner-alice-job",
        AssessRequest(vuln_id="CVE-2026-A", component_name="component-a"),
        owner="alice",
    )
    bob = Job(
        "owner-bob-job",
        AssessRequest(vuln_id="CVE-2026-B", component_name="component-b"),
        owner="bob",
    )
    app.state.jobs[alice.id] = alice
    app.state.jobs[bob.id] = bob
    try:
        alice_headers = {"X-Agentyzer-Owner": "alice"}
        listed = client.get("/jobs", headers=alice_headers)
        assert listed.status_code == 200
        assert [job["job_id"] for job in listed.json()["jobs"]] == [alice.id]
        assert listed.json()["backend"]["jobs"]["known_jobs"] == 1

        assert client.get(f"/jobs/{bob.id}", headers=alice_headers).status_code == 404
        assert client.delete(f"/jobs/{bob.id}", headers=alice_headers).status_code == 404

        denied = client.get("/jobs", headers={"X-Agentyzer-Owner": "*"})
        assert denied.status_code == 403

        admin = client.get("/jobs", headers=ADMIN_HEADERS)
        assert admin.status_code == 200
        admin_ids = {job["job_id"] for job in admin.json()["jobs"]}
        assert {alice.id, bob.id}.issubset(admin_ids)
    finally:
        app.state.jobs.pop(alice.id, None)
        app.state.jobs.pop(bob.id, None)


def test_job_compaction_and_follow_up_endpoint(client, monkeypatch):
    async def fake_run_job(job: Job):
        job.status = JobStatus.completed
        job.finished_at = "2026-07-06T10:01:00+00:00"

    monkeypatch.setattr("src.main._run_job", fake_run_job)
    parent = _seed_completed_parent_job()

    try:
        compact_response = client.post(f"/jobs/{parent.id}/compact")
        assert compact_response.status_code == 200
        compact = compact_response.json()
        assert compact["job_id"] == parent.id
        assert compact["context"]["target"]["component_name"] == "keycloak-extension"
        assert compact["context"]["summary"] == "Extension is not affected."
        assert "Extension is not affected" in compact["prompt_context"]

        follow_response = client.post(
            f"/jobs/{parent.id}/follow-up",
            json={
                "question": "Is Keycloak itself vulnerable?",
                "component_name": "keycloak",
            },
        )
        assert follow_response.status_code == 200
        follow_payload = follow_response.json()
        follow_job = app.state.jobs[follow_payload["job_id"]]
        assert follow_job.parent_job_id == parent.id
        assert follow_job.follow_up_question == "Is Keycloak itself vulnerable?"
        assert follow_job.request.component_name == "keycloak"
        assert follow_job.request.vuln_id == "CVE-2026-FOLLOW"
        assert "Compact parent context" in follow_job.request.user_guidance
        assert "Only extension-specific code was checked" in follow_job.request.user_guidance
    finally:
        for job_id in list(app.state.jobs):
            if job_id == parent.id or getattr(app.state.jobs[job_id], "parent_job_id", None) == parent.id:
                app.state.jobs.pop(job_id, None)


def test_assess_inconclusive(client):
    # Temporarily clear defaults so unknown components can't resolve via template
    original_repos = app.state.repos
    app.state.repos = {"components": {}}
    try:
        payload = {"vuln_id": "CVE-0000-0000", "component_name": "unknown-component"}
        r = client.post("/assess", json=payload, params={"sync": True})
        assert r.status_code == 200
        data = r.json()
        assert data["assessment"]["verdict"] == "Inconclusive"
        assert data["assessment"]["affected"] is False
        assert isinstance(data["steps"], list)
    finally:
        app.state.repos = original_repos


def test_openapi_contains_descriptions_and_examples(client):
    r = client.get("/openapi.json")
    assert r.status_code == 200

    spec = r.json()
    assert spec["info"]["title"] == "Agentic Vulnerability Analyzer"
    assert spec["info"]["version"] == "0.1.0"
    assert (
        spec["paths"]["/assess"]["post"]["summary"]
        == "Start a vulnerability assessment"
    )

    request_examples = spec["paths"]["/assess"]["post"]["requestBody"]["content"][
        "application/json"
    ]["examples"]
    assert "syncAssessment" in request_examples
    assert request_examples["syncAssessment"]["value"]["component_name"] == "benchmark"
    assert request_examples["syncAssessment"]["value"]["debug"] is True

    assessment_schema = spec["components"]["schemas"]["AssessResponse"]
    assert "example" in assessment_schema
    assert (
        assessment_schema["example"]["assessment"]["adjusted_cvss"]["version_context"][
            "detected_version"
        ]
        == "2.0.0"
    )
    assert (
        assessment_schema["example"]["assessment"]["version_analysis"][
            "detected_version"
        ]
        == "2.0.0"
    )
    version_context = assessment_schema["example"]["assessment"]["adjusted_cvss"][
        "version_context"
    ]
    assert version_context["comparison_inputs"]["locked_version"] == "2.0.0"
    assert version_context["comparison_inputs"]["affected_versions_count"] == 2
    assert version_context["comparison_trace"][-1].endswith(
        "MATCH in explicit affected versions list"
    )
    assert assessment_schema["example"]["assessment"]["reasoning"] == (
        "The dependency is present, the locked version is inside the advisory range, "
        "and the vulnerable API is reachable from application code."
    )
    dependency_presence = assessment_schema["example"]["assessment"][
        "dependency_presence"
    ]
    assert dependency_presence["found"] is True
    assert dependency_presence["repo_found"] is True
    assert dependency_presence["sbom_attributed"] is True
    assert dependency_presence["presence_basis"] == "direct"
    researcher_view = assessment_schema["example"]["assessment"]["researcher_view"]
    assert (
        researcher_view["findings"][1]
        == "Dependency presence: found as a direct dependency"
    )

    remediation_view = assessment_schema["example"]["assessment"]["remediation_view"]
    assert remediation_view["status"] == "action_needed"
    assert remediation_view["recommendations"][-1].startswith("Rerun Agentyzer")

    audit_view = assessment_schema["example"]["assessment"]["audit_view"]
    assert audit_view["status"] == "pass"
    assert audit_view["consistency"] == "strong"
    assert audit_view["downgrade_target"] is False
    assert audit_view["downgrade_supported"] is True
    assert audit_view["checks"][0].startswith("Supports verdict")

    cvss_schema = spec["components"]["schemas"]["CvssAdjustment"]
    assert "description" in cvss_schema["properties"]["version_context"]

    assessment_model = spec["components"]["schemas"]["Assessment"]
    dep_presence_ref = assessment_model["properties"]["dependency_presence"]["anyOf"]
    assert dep_presence_ref[0]["$ref"].endswith("/DependencyPresence")

    job_status_schema = spec["components"]["schemas"]["JobStatusResponse"]
    assert "progress" in job_status_schema["properties"]
    assert "configuration" in job_status_schema["properties"]
    assert "backend" in job_status_schema["properties"]

    assert "/configuration" in spec["paths"]
    health_schema = spec["components"]["schemas"]["HealthResponse"]
    assert "configuration" in health_schema["properties"]
    assert "backend" in health_schema["properties"]
    assert "ServiceConfiguration" in spec["components"]["schemas"]
    assert "BackendInformation" in spec["components"]["schemas"]


def test_job_status_response_includes_live_progress_snapshot():
    job = Job(
        "job-123",
        AssessRequest(vuln_id="CVE-2024-49766", component_name="benchmark"),
    )
    _apply_progress_event(
        job,
        {
            "phase": "start",
            "step": "scan_code",
            "title": "Code Scan",
            "agent": "code_scanner",
            "activity": "Searching source files for vulnerable symbols and usage",
        },
    )
    _apply_progress_event(
        job,
        {
            "phase": "completed",
            "step": "filter_advisory",
            "title": "Advisory Relevance Filter",
            "agent": "verdict",
            "activity": "Checking whether the advisory applies to this component",
            "status": "completed",
            "report": {"status": "completed", "findings": {"relevant": True}},
        },
    )

    response = _job_status_response(job)

    assert response.progress.percent == 8
    assert response.progress.completed_steps == 1
    assert response.progress.total_steps == 12
    assert response.progress.current_step == "scan_code"
    assert response.progress.current_agent == "code_scanner"
    assert response.progress.active_agents[0].activity.endswith("usage")
    assert response.progress.step_statuses["filter_advisory"] == "completed"


def test_job_status_response_updates_model_wait_heartbeat():
    job = Job(
        "job-heartbeat",
        AssessRequest(vuln_id="CVE-2024-49766", component_name="benchmark"),
    )
    _apply_progress_event(
        job,
        {
            "phase": "start",
            "step": "llm_analyze_code",
            "title": "LLM Reachability Analysis",
            "agent": "code_scanner",
            "activity": "Assessing whether vulnerable code paths appear reachable",
        },
    )
    _apply_progress_event(
        job,
        {
            "phase": "heartbeat",
            "step": "llm_analyze_code",
            "title": "LLM Reachability Analysis",
            "agent": "code_scanner",
            "activity": "Waiting for model response during LLM Reachability Analysis",
        },
    )

    response = _job_status_response(job)

    assert response.progress.current_activity == (
        "Waiting for model response during LLM Reachability Analysis"
    )
    assert response.progress.active_agents[0].activity.startswith(
        "Waiting for model response"
    )
    assert response.progress.step_statuses["llm_analyze_code"] == "running"


def test_job_status_response_adjusts_total_steps_for_filtered_advisory():
    job = Job(
        "job-456",
        AssessRequest(vuln_id="CVE-2024-49766", component_name="benchmark"),
    )
    _apply_progress_event(
        job,
        {
            "phase": "completed",
            "step": "filter_advisory",
            "title": "Advisory Relevance Filter",
            "agent": "verdict",
            "activity": "Checking whether the advisory applies to this component",
            "status": "filtered",
            "report": {"status": "filtered", "findings": {"relevant": False}},
        },
    )

    response = _job_status_response(job)

    assert response.progress.total_steps == 4
    assert response.progress.percent == 25


def test_app_startup_fails_when_required_prompt_key_is_missing(monkeypatch, tmp_path):
    config_dir = tmp_path / "config"
    prompts_dir = config_dir / "prompts"
    prompts_dir.mkdir(parents=True)

    (config_dir / "repos.yaml").write_text("components: {}\n")
    (prompts_dir / "common.yaml").write_text(
        "web_research_addendum: ok\nresearch_continuation_instruction: ok\n"
    )
    (prompts_dir / "code_reachability.yaml").write_text(
        "system: ok\nanalysis_protocol: ok\nresponse_contract: ok\n"
    )
    (prompts_dir / "deep_analysis.yaml").write_text(
        "system: ok\nanalysis_protocol: ok\nresponse_contract: ok\n"
    )
    (prompts_dir / "transitive_analysis.yaml").write_text(
        "system: ok\nanalysis_protocol: ok\nresponse_contract: ok\n"
    )
    (prompts_dir / "verdict.yaml").write_text(
        "system: ok\nanalysis_protocol: ok\nresponse_contract: ok\nreasoning_contract: ok\n"
    )
    (prompts_dir / "advisory_relevance.yaml").write_text(
        "system: ok\ninstructions: ok\n"
    )

    monkeypatch.setattr(prompt_registry, "_CONFIG_DIR", config_dir)
    monkeypatch.setattr(prompt_registry, "_PROMPTS_DIR", prompts_dir)
    monkeypatch.setattr("src.main._CONFIG_DIR", str(config_dir))
    prompt_registry.clear_prompt_cache()

    with pytest.raises(ValueError, match="input_preamble"):
        with TestClient(app) as client:
            client.get("/health")

    prompt_registry.clear_prompt_cache()


class _FakeOpenWebUIResponse:
    def __init__(self, *, status_code=200, json_data=None, text="", lines=None):
        self.status_code = status_code
        self._json_data = json_data
        self.text = text
        self._lines = lines or [
            'data: {"choices": [{"delta": {"content": "ok"}}]}',
            "data: [DONE]",
        ]

    def raise_for_status(self):
        if self.status_code >= 400:
            request = httpx.Request(
                "POST", "https://webui.vp.apps.ge-healthcare.net/api/chat/completions"
            )
            content = None
            headers = None
            if self._json_data is not None:
                content = json.dumps(self._json_data).encode("utf-8")
                headers = {"Content-Type": "application/json"}
            elif self.text:
                content = self.text.encode("utf-8")
            response = httpx.Response(
                self.status_code,
                request=request,
                content=content,
                headers=headers,
            )
            raise httpx.HTTPStatusError(
                "400 Client Error: Bad Request for url",
                request=request,
                response=response,
            )

    async def aiter_lines(self):
        for line in self._lines:
            yield line

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _FakeOpenWebUIClient:
    def __init__(self, response, capture):
        self._responses = response if isinstance(response, list) else [response]
        self._capture = capture

    def stream(self, method, url, *, json, headers):
        self._capture.setdefault("requests", []).append(copy.deepcopy(json))
        self._capture["method"] = method
        self._capture["url"] = url
        self._capture["json"] = json
        self._capture["headers"] = headers
        if len(self._responses) > 1:
            return self._responses.pop(0)
        return self._responses[0]

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


def test_openwebui_client_includes_server_error_detail(monkeypatch):
    capture = {}
    response = _FakeOpenWebUIResponse(
        status_code=400,
        json_data={"detail": "Model not found"},
    )

    def fake_async_client(**kwargs):
        return _FakeOpenWebUIClient(response, capture)

    monkeypatch.setattr("src.llm.openwebui_client.async_client", fake_async_client)

    client = OpenWebUIClient(
        host="https://webui.vp.apps.ge-healthcare.net",
        model="mistral",
        api_key="secret",
    )

    with pytest.raises(RuntimeError, match="Model not found"):
        asyncio.run(client.generate("hello"))


def test_openwebui_client_sends_openai_compatible_payload(monkeypatch):
    capture = {}
    response = _FakeOpenWebUIResponse(status_code=200)

    def fake_async_client(**kwargs):
        return _FakeOpenWebUIClient(response, capture)

    monkeypatch.setattr("src.llm.openwebui_client.async_client", fake_async_client)

    client = OpenWebUIClient(
        host="https://webui.vp.apps.ge-healthcare.net",
        model="mistral",
        api_key="secret",
    )

    result = asyncio.run(
        client.generate("hello", system="system prompt", num_predict=123)
    )

    assert result == "ok"
    assert capture["method"] == "POST"
    assert (
        capture["url"] == "https://webui.vp.apps.ge-healthcare.net/api/chat/completions"
    )
    assert capture["headers"] == {"Authorization": "Bearer secret"}
    assert capture["json"] == {
        "model": "mistral",
        "messages": [
            {"role": "system", "content": "system prompt"},
            {"role": "user", "content": "hello"},
        ],
        "parent_id": None,
        "stream": True,
        "stream_options": {"include_usage": True},
        "temperature": 0.0,
        "max_tokens": 123,
    }
    assert client.conversation_trace[0]["messages"] == [
        {"role": "system", "content": "system prompt"},
        {"role": "user", "content": "hello"},
    ]
    assert client.conversation_trace[0]["response"] == {
        "role": "assistant",
        "content": "ok",
    }
    assert client.conversation_trace[0]["status"] == "completed"


def test_openwebui_client_retries_with_smaller_output_on_context_error(monkeypatch):
    capture = {}
    context_error = (
        "This model's maximum context length is 131072 tokens. However, you "
        "requested 4096 output tokens and your prompt contains at least 126977 "
        "input tokens, for a total of at least 131073 tokens. Please reduce the "
        "length of the input prompt or the number of requested output tokens."
    )
    responses = [
        _FakeOpenWebUIResponse(status_code=400, json_data={"detail": context_error}),
        _FakeOpenWebUIResponse(status_code=200),
    ]

    def fake_async_client(**kwargs):
        return _FakeOpenWebUIClient(responses, capture)

    monkeypatch.setattr("src.llm.openwebui_client.async_client", fake_async_client)

    client = OpenWebUIClient(
        host="https://webui.vp.apps.ge-healthcare.net",
        model="mistral",
        api_key="secret",
    )

    result = asyncio.run(client.generate("hello", num_predict=4096))

    assert result == "ok"
    assert len(capture["requests"]) == 2
    assert capture["requests"][0]["max_tokens"] == 4096
    assert capture["requests"][1]["max_tokens"] == 3839
    request_trace = client.conversation_trace[0]["request"]
    assert request_trace["max_tokens"] == 3839
    assert "context_adaptations" in request_trace


def test_openwebui_client_truncates_prompt_for_configured_context_window(monkeypatch):
    capture = {}
    response = _FakeOpenWebUIResponse(status_code=200)

    def fake_async_client(**kwargs):
        return _FakeOpenWebUIClient(response, capture)

    monkeypatch.setattr("src.llm.openwebui_client.async_client", fake_async_client)

    client = OpenWebUIClient(
        host="https://webui.vp.apps.ge-healthcare.net",
        model="mistral",
        api_key="secret",
        context_window_tokens=1000,
        context_safety_margin=0,
        min_completion_tokens=100,
    )
    prompt = "source-line\n" * 2000

    asyncio.run(client.generate(prompt, num_predict=500))

    sent_prompt = capture["json"]["messages"][0]["content"]
    assert len(sent_prompt) < len(prompt)
    assert "truncated by Agentyzer" in sent_prompt
    assert capture["json"]["max_tokens"] <= 500
    assert "context_adaptations" in client.conversation_trace[0]["request"]


def test_openwebui_client_sends_and_captures_native_tool_calls(monkeypatch):
    capture = {}
    response = _FakeOpenWebUIResponse(
        status_code=200,
        lines=[
            "data: "
            + json.dumps(
                {
                    "choices": [
                        {
                            "delta": {
                                "tool_calls": [
                                    {
                                        "index": 0,
                                        "id": "call_1",
                                        "type": "function",
                                        "function": {
                                            "name": "search_web",
                                            "arguments": '{"query":"Keycloak',
                                        },
                                    }
                                ]
                            }
                        }
                    ]
                }
            ),
            "data: "
            + json.dumps(
                {
                    "choices": [
                        {
                            "delta": {
                                "tool_calls": [
                                    {
                                        "index": 0,
                                        "function": {
                                            "arguments": ' Netty CVE"}',
                                        },
                                    }
                                ]
                            }
                        }
                    ]
                }
            ),
            "data: [DONE]",
        ],
    )

    def fake_async_client(**kwargs):
        return _FakeOpenWebUIClient(response, capture)

    monkeypatch.setattr("src.llm.openwebui_client.async_client", fake_async_client)

    client = OpenWebUIClient(
        host="https://webui.vp.apps.ge-healthcare.net",
        model="mistral",
        api_key="secret",
    )
    tools = [
        {
            "type": "function",
            "function": {
                "name": "search_web",
                "parameters": {"type": "object"},
            },
        }
    ]

    result = asyncio.run(
        client.chat_completion(
            [{"role": "user", "content": "research keycloak"}],
            tools=tools,
            tool_choice="auto",
        )
    )

    assert capture["json"]["tools"] == tools
    assert capture["json"]["tool_choice"] == "auto"
    assert result["tool_calls"] == [
        {
            "id": "call_1",
            "type": "function",
            "function": {
                "name": "search_web",
                "arguments": '{"query":"Keycloak Netty CVE"}',
            },
        }
    ]
    assert client.conversation_trace[0]["request"]["tools"] == ["search_web"]
    assert client.conversation_trace[0]["response"]["tool_calls"] == result[
        "tool_calls"
    ]


def test_openwebui_client_retries_remote_disconnect_once(monkeypatch):
    capture = {"attempts": 0}
    responses = [
        httpx.RemoteProtocolError("Server disconnected without sending a response."),
        _FakeOpenWebUIResponse(status_code=200),
    ]

    class SequencedOpenWebUIClient:
        def stream(self, method, url, *, json, headers):
            capture["attempts"] += 1
            capture["method"] = method
            capture["url"] = url
            capture["json"] = json
            capture["headers"] = headers
            next_response = responses.pop(0)
            if isinstance(next_response, Exception):
                raise next_response
            return next_response

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

    def fake_async_client(**kwargs):
        return SequencedOpenWebUIClient()

    monkeypatch.setattr("src.llm.openwebui_client.async_client", fake_async_client)

    client = OpenWebUIClient(
        host="https://webui.vp.apps.ge-healthcare.net",
        model="mistral",
        api_key="secret",
    )

    result = asyncio.run(client.generate("hello"))

    assert result == "ok"
    assert capture["attempts"] == 2
    assert client.last_error == ""


def test_openwebui_client_captures_stream_usage(monkeypatch):
    capture = {}
    response = _FakeOpenWebUIResponse(
        status_code=200,
        lines=[
            'data: {"choices": [{"delta": {"content": "ok"}}]}',
            'data: {"choices": [], "usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}}',
            "data: [DONE]",
        ],
    )

    def fake_async_client(**kwargs):
        return _FakeOpenWebUIClient(response, capture)

    monkeypatch.setattr("src.llm.openwebui_client.async_client", fake_async_client)

    client = OpenWebUIClient(
        host="https://webui.vp.apps.ge-healthcare.net",
        model="mistral",
        api_key="secret",
    )

    result = asyncio.run(client.generate("hello"))

    assert result == "ok"
    assert client.last_usage == {
        "prompt_tokens": 11,
        "completion_tokens": 7,
        "total_tokens": 18,
    }
    assert client.conversation_trace[0]["usage"] == client.last_usage


def test_openwebui_client_payload_serializes_advisory_text(monkeypatch):
    capture = {}
    response = _FakeOpenWebUIResponse(status_code=200)

    def fake_async_client(**kwargs):
        return _FakeOpenWebUIClient(response, capture)

    monkeypatch.setattr("src.llm.openwebui_client.async_client", fake_async_client)

    prompt = (
        "fast-uri vulnerable to path traversal via percent-encoded dot segments\n"
        "### Impact `fast-uri` v3.1.0 and earlier decodes percent-encoded path separators "
        "(`%2F`) and dot segments (`%2E`) before applying dot-segment removal in "
        "`normalize()` and `equal()`."
    )

    client = OpenWebUIClient(
        host="https://webui.vp.apps.ge-healthcare.net",
        model="mistral",
        api_key="secret",
    )

    asyncio.run(client.generate(prompt))

    encoded = json.dumps(capture["json"])
    assert "%2F" in encoded
    assert "%2E" in encoded
    assert "normalize()" in encoded


def test_openwebui_client_payload_serializes_quoted_advisory_text(monkeypatch):
    capture = {}
    response = _FakeOpenWebUIResponse(status_code=200)

    def fake_async_client(**kwargs):
        return _FakeOpenWebUIClient(response, capture)

    monkeypatch.setattr("src.llm.openwebui_client.async_client", fake_async_client)

    prompt = """fast-xml-builder allows attribute values with unwanted quotes to bypass malicious or unwanted attributes
# Summary When an input data has quotes in attribute values but process entities is not enabled, it breaks the attribute value into multiple attributes. This gives the room for an attacker to insert unwanted attributes to the XML/HTML.
## Detail Malicious Input
```
{ a: { \"@_attr\": '\" onClick=\"alert(1)' } }
```
Output
```xml
<a attr=\"\" onClick=\"alert(1)\"></a>
```
### Workarounds If you're not ignoring attributes then keep processEntities flag true.
"""

    client = OpenWebUIClient(
        host="https://webui.vp.apps.ge-healthcare.net",
        model="mistral",
        api_key="secret",
    )

    asyncio.run(client.generate(prompt))

    assert capture["json"]["messages"][0] == {"role": "user", "content": prompt}

    encoded = json.dumps(capture["json"])
    decoded = json.loads(encoded)

    assert '\\"@_attr\\"' in encoded
    assert 'onClick=\\"alert(1)' in encoded
    assert decoded["messages"][0]["content"] == prompt
