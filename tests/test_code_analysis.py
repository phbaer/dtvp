import asyncio
import os
import threading
import time
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import dtvp.agentizer_integration as agentizer
import dtvp.code_analysis_integration as code_analysis
from dtvp import main
from dtvp.auto_analysis_services import (
    AutoAnalysisQueueCandidate,
    AutoAnalysisQueuePlan,
    AutoAnalysisSweepPlan,
)
from dtvp.analysis_queue_services import (
    AnalysisQueueServiceDeps,
    AnalysisQueueRuntimeDeps,
    process_analysis_queue_item,
    run_analysis_queue_worker,
)


class DummyResponse:
    def __init__(self, data):
        self._data = data

    def raise_for_status(self):
        return None

    def json(self):
        return self._data


@pytest.fixture(autouse=True)
def override_auth():
    main.app.dependency_overrides[main.get_current_user] = lambda: "testuser"
    with patch("dtvp.main.get_user_role", return_value="REVIEWER"):
        yield
    main.app.dependency_overrides.pop(main.get_current_user, None)


@pytest.fixture(autouse=True)
def reset_analysis_queue():
    main.analysis_queue._items.clear()
    main.analysis_queue._order.clear()
    main.analysis_queue._event.clear()
    main.analysis_queue._running = True
    yield
    main.analysis_queue._items.clear()
    main.analysis_queue._order.clear()
    main.analysis_queue._event.clear()
    main.analysis_queue._running = True


@pytest.fixture(autouse=True)
def reset_auto_analysis_sweep_state():
    original_state = dict(main.auto_analysis_sweep_state)
    original_task = main.auto_analysis_sweep_task
    main.auto_analysis_sweep_task = None
    main.shutdown_auto_analysis_sweep_executor()
    main.auto_analysis_sweep_state.update(
        {
            "running": False,
            "last_started_at": None,
            "last_finished_at": None,
            "last_queued_count": None,
            "last_error": None,
            "last_trigger": None,
            "next_run_at": None,
        }
    )
    yield
    main.shutdown_auto_analysis_sweep_executor()
    main.auto_analysis_sweep_task = original_task
    main.auto_analysis_sweep_state.clear()
    main.auto_analysis_sweep_state.update(original_state)


@pytest.fixture(autouse=True)
def disable_global_analysis_worker(monkeypatch):
    async def _noop_worker():
        return None

    monkeypatch.setattr(main.analysis_queue, "worker", _noop_worker)
    yield


@pytest.mark.asyncio
@pytest.mark.parametrize(
    (
        "integration_module",
        "settings_cls",
        "client_cls",
        "env_name",
    ),
    [
        (
            agentizer,
            agentizer.AgenyzerSettings,
            agentizer.AgenyzerClient,
            "DTVP_AGENYZER_URL",
        ),
        (
            code_analysis,
            code_analysis.CodeAnalysisSettings,
            code_analysis.CodeAnalysisClient,
            "DTVP_CODE_ANALYSIS_URL",
        ),
    ],
)
async def test_agent_client_builds_payloads_and_calls_httpx(
    integration_module, settings_cls, client_cls, env_name, monkeypatch
):
    monkeypatch.setenv(env_name, "http://example.com/")
    monkeypatch.setenv(
        env_name.replace("_URL", "_SERVICE_TOKEN"),
        "test-only-service-token-1234567890abcdef",
    )

    dummy_client = MagicMock()
    dummy_client.get = AsyncMock(
        side_effect=[
            DummyResponse({"health": "ok"}),
            DummyResponse({"status": "running"}),
            DummyResponse({"jobs": [{"job_id": "job-1"}]}),
            DummyResponse({"result": "done"}),
        ]
    )
    dummy_client.post = AsyncMock(
        side_effect=[
            DummyResponse({"job_id": "job-1"}),
            DummyResponse({"job_id": "job-2"}),
        ]
    )
    dummy_client.delete = AsyncMock(return_value=DummyResponse({}))
    dummy_client.aclose = AsyncMock()

    monkeypatch.setattr(
        integration_module.httpx, "AsyncClient", MagicMock(return_value=dummy_client)
    )

    settings = settings_cls()
    assert settings.enabled is True
    assert settings.base_url == "http://example.com"

    client = client_cls(settings=settings)

    async_client_call = integration_module.httpx.AsyncClient.call_args
    assert async_client_call.kwargs["headers"] == {
        "Authorization": "Bearer test-only-service-token-1234567890abcdef",
        "X-Agentyzer-Owner": "service",
    }

    assert await client.health() == {"health": "ok"}
    assert await client.start_assessment(
        vuln_id="CVE-2024-1000",
        component_name="libA",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        user_guidance="Please review",
        model="gpt-test",
        llm_backend="openwebui",
        llm_provider="OpenWebUI",
        focus_path="root>libA",
        dependency_paths=[["root", "libA"]],
        affected_product_versions=["1.0.0", "1.1.0"],
        debug=True,
    ) == {"job_id": "job-1"}

    assert await client.start_assessment_sync(
        vuln_id="CVE-2024-1001",
        component_name="libB",
        affected_product_versions=["2.0.0"],
        debug=False,
    ) == {"job_id": "job-2"}

    assert await client.get_job_status("job-1") == {"status": "running"}
    assert await client.list_jobs() == {"jobs": [{"job_id": "job-1"}]}
    assert await client.get_job_result("job-1") == {"result": "done"}
    assert await client.delete_job("job-1") is None
    await client.close()

    first_post = dummy_client.post.await_args_list[0]
    assert first_post.kwargs["json"]["affected_product_versions"] == [
        "1.0.0",
        "1.1.0",
    ]

    assert dummy_client.post.call_count == 2
    assert dummy_client.post.call_args_list[1].kwargs["params"] == {"sync": "true"}
    assert dummy_client.post.call_args_list[1].kwargs["json"][
        "affected_product_versions"
    ] == ["2.0.0"]
    assert (
        dummy_client.post.call_args_list[0].kwargs["json"]["user_guidance"]
        == "Please review"
    )
    payload = dummy_client.post.call_args_list[0].kwargs["json"]
    assert payload["model"] == "gpt-test"
    assert payload["llm_backend"] == "openwebui"
    assert payload["llm_provider"] == "OpenWebUI"
    dummy_client.aclose.assert_awaited_once()


def test_legacy_agenyzer_client_delegates_to_canonical_implementation():
    assert issubclass(agentizer.AgenyzerClient, code_analysis.CodeAnalysisClient)
    assert (
        agentizer.AgenyzerClient.start_assessment
        is code_analysis.CodeAnalysisClient.start_assessment
    )


@pytest.mark.parametrize(
    ("settings_cls", "validator", "url_env", "token_env", "token_file_env"),
    [
        (
            agentizer.AgenyzerSettings,
            agentizer.validate_agenyzer_configuration,
            "DTVP_AGENYZER_URL",
            "DTVP_AGENYZER_SERVICE_TOKEN",
            "DTVP_AGENYZER_SERVICE_TOKEN_FILE",
        ),
        (
            code_analysis.CodeAnalysisSettings,
            code_analysis.validate_code_analysis_configuration,
            "DTVP_CODE_ANALYSIS_URL",
            "DTVP_CODE_ANALYSIS_SERVICE_TOKEN",
            "DTVP_CODE_ANALYSIS_SERVICE_TOKEN_FILE",
        ),
    ],
)
def test_enabled_production_analyzer_requires_service_token(
    settings_cls,
    validator,
    url_env,
    token_env,
    token_file_env,
    monkeypatch,
):
    monkeypatch.setenv("DTVP_ENVIRONMENT", "production")
    monkeypatch.setenv(url_env, "http://agentyzer:8000")
    monkeypatch.delenv(token_env, raising=False)
    monkeypatch.delenv(token_file_env, raising=False)

    with pytest.raises(RuntimeError, match="SERVICE_TOKEN"):
        validator(settings_cls())


def test_enabled_production_code_analyzer_requires_distinct_admin_token(
    monkeypatch,
):
    token = "test-only-service-token-1234567890abcdef"
    monkeypatch.setenv("DTVP_ENVIRONMENT", "production")
    monkeypatch.setenv("DTVP_CODE_ANALYSIS_URL", "http://agentyzer:8000")
    monkeypatch.setenv("DTVP_CODE_ANALYSIS_SERVICE_TOKEN", token)
    monkeypatch.delenv("DTVP_CODE_ANALYSIS_ADMIN_TOKEN", raising=False)
    monkeypatch.delenv("DTVP_CODE_ANALYSIS_ADMIN_TOKEN_FILE", raising=False)

    with pytest.raises(RuntimeError, match="ADMIN_TOKEN"):
        code_analysis.validate_code_analysis_configuration()

    monkeypatch.setenv("DTVP_CODE_ANALYSIS_ADMIN_TOKEN", token)
    with pytest.raises(RuntimeError, match="must differ"):
        code_analysis.validate_code_analysis_configuration()


def test_code_analysis_client_uses_admin_token_for_wide_scope(monkeypatch):
    monkeypatch.setenv("DTVP_CODE_ANALYSIS_URL", "http://example.com")
    monkeypatch.setenv(
        "DTVP_CODE_ANALYSIS_SERVICE_TOKEN",
        "test-only-service-token-1234567890abcdef",
    )
    monkeypatch.setenv(
        "DTVP_CODE_ANALYSIS_ADMIN_TOKEN",
        "test-only-admin-token-1234567890abcdefgh",
    )
    client_factory = MagicMock()
    monkeypatch.setattr(code_analysis.httpx, "AsyncClient", client_factory)

    code_analysis.CodeAnalysisClient(
        settings=code_analysis.CodeAnalysisSettings(),
        owner="*",
    )

    assert client_factory.call_args.kwargs["headers"] == {
        "Authorization": "Bearer test-only-admin-token-1234567890abcdefgh",
        "X-Agentyzer-Owner": "*",
    }


@pytest.mark.asyncio
async def test_code_analysis_client_compares_benchmark(monkeypatch):
    monkeypatch.setenv("DTVP_CODE_ANALYSIS_URL", "http://example.com/")
    monkeypatch.setenv("DTVP_CODE_ANALYSIS_MODEL", "gpt-benchmark")

    dummy_client = MagicMock()
    dummy_client.post = AsyncMock(
        return_value=DummyResponse({"comparison_method": "agentyzer_probabilistic"})
    )
    dummy_client.aclose = AsyncMock()
    monkeypatch.setattr(
        code_analysis.httpx, "AsyncClient", MagicMock(return_value=dummy_client)
    )

    client = code_analysis.CodeAnalysisClient(settings=code_analysis.CodeAnalysisSettings())
    result = await client.compare_benchmark({"rating": {"score": 4}})

    assert result == {"comparison_method": "agentyzer_probabilistic"}
    assert dummy_client.post.await_args.args[0] == "http://example.com/benchmark/compare"
    assert dummy_client.post.await_args.kwargs["json"] == {
        "benchmark": {"rating": {"score": 4}},
        "model": "gpt-benchmark",
    }
    await client.close()


def test_code_analysis_endpoints_require_configuration(client):
    with patch.dict(os.environ, {"DTVP_CODE_ANALYSIS_URL": ""}):
        response = client.get("/api/code-analysis/health")
        assert response.status_code == 503
        assert "not configured" in response.json()["detail"]


def test_code_analysis_endpoints_call_client_methods(client):
    with patch.dict(os.environ, {"DTVP_CODE_ANALYSIS_URL": "http://example.com"}):
        with patch(
            "dtvp.main.CodeAnalysisClient.start_assessment",
            new=AsyncMock(return_value={"job_id": "job-1"}),
        ) as assess_mock:
            response = client.post(
                "/api/code-analysis/assess",
                json={
                    "vuln_id": "CVE-2024-1000",
                    "component_name": "libA",
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "user_guidance": "Please review",
                    "focus_path": "root>libA",
                    "dependency_paths": [["root", "libA"]],
                    "debug": True,
                },
            )

            assert response.status_code == 200
            assert response.json() == {"job_id": "job-1"}
            assess_mock.assert_awaited_once()
            assert assess_mock.await_args.kwargs["vuln_id"] == "CVE-2024-1000"

        with patch(
            "dtvp.main.CodeAnalysisClient.get_job_status",
            new=AsyncMock(return_value={"status": "running"}),
        ):
            response = client.get("/api/code-analysis/jobs/job-1")
            assert response.status_code == 200
            assert response.json()["status"] == "running"

        with patch(
            "dtvp.main.CodeAnalysisClient.get_job_result",
            new=AsyncMock(return_value={"result": "done"}),
        ):
            response = client.get("/api/code-analysis/jobs/job-1/result")
            assert response.status_code == 200
            assert response.json()["result"] == "done"

        with patch(
            "dtvp.main.CodeAnalysisClient.health",
            new=AsyncMock(return_value={"healthy": True}),
        ):
            response = client.get("/api/code-analysis/health")
            assert response.status_code == 200
            assert response.json() == {"healthy": True}


def test_code_analysis_auto_sweep_status_and_manual_run(client):
    worker_started = threading.Event()
    release_worker = threading.Event()
    plan = AutoAnalysisSweepPlan(
        queue_plans=(
            AutoAnalysisQueuePlan(
                candidates=(
                    AutoAnalysisQueueCandidate(
                        vuln_id="CVE-2026-MANUAL-1",
                        component_name="owned-api",
                    ),
                    AutoAnalysisQueueCandidate(
                        vuln_id="CVE-2026-MANUAL-2",
                        component_name="owned-worker",
                    ),
                )
            ),
        )
    )

    def blocking_worker():
        worker_started.set()
        release_worker.wait(timeout=2)
        return plan

    with patch.dict(
        os.environ,
        {
            "DTVP_CODE_ANALYSIS_URL": "http://example.com",
            "DTVP_AUTO_CODE_ANALYSIS_ENABLED": "true",
            "DTVP_AUTO_CODE_ANALYSIS_SWEEP_SECONDS": "120",
        },
    ):
        with patch(
            "dtvp.main._run_auto_analysis_sweep_worker",
            side_effect=blocking_worker,
        ) as worker_mock:
            status_response = client.get("/api/code-analysis/auto-sweep")
            assert status_response.status_code == 200
            status = status_response.json()
            assert status["active"] is True
            assert status["interval_seconds"] == 120
            assert status["last_queued_count"] is None

            run_response = client.post("/api/code-analysis/auto-sweep/run")
            assert run_response.status_code == 200
            payload = run_response.json()

    assert payload["active"] is True
    assert payload["running"] is True
    assert payload["last_trigger"] == "manual"
    assert payload["last_started_at"]
    assert payload["last_finished_at"] is None
    assert worker_started.wait(timeout=1)
    assert worker_mock.call_count == 1

    release_worker.set()
    for _ in range(40):
        status_response = client.get("/api/code-analysis/auto-sweep")
        status = status_response.json()
        if status["running"] is False and status["last_queued_count"] == 2:
            break
        time.sleep(0.05)

    assert status["running"] is False
    assert status["last_queued_count"] == 2
    assert status["last_finished_at"]
    assert len(main.analysis_queue.list_all()) == 2


def test_code_analysis_auto_sweep_manual_run_deduplicates_active_worker(client):
    worker_started = threading.Event()
    release_worker = threading.Event()

    def blocking_worker():
        worker_started.set()
        release_worker.wait(timeout=2)
        return AutoAnalysisSweepPlan()

    with patch.dict(
        os.environ,
        {
            "DTVP_CODE_ANALYSIS_URL": "http://example.com",
            "DTVP_AUTO_CODE_ANALYSIS_ENABLED": "true",
        },
    ):
        with patch(
            "dtvp.main._run_auto_analysis_sweep_worker",
            side_effect=blocking_worker,
        ) as worker_mock:
            first = client.post("/api/code-analysis/auto-sweep/run")
            assert first.status_code == 200
            assert first.json()["running"] is True
            assert worker_started.wait(timeout=1)

            second = client.post("/api/code-analysis/auto-sweep/run")
            assert second.status_code == 200
            assert second.json()["running"] is True
            assert worker_mock.call_count == 1

            release_worker.set()


@pytest.mark.asyncio
async def test_scheduled_auto_sweep_waits_before_first_run(monkeypatch):
    sweep_mock = AsyncMock()

    async def stop_at_first_sleep(seconds):
        assert seconds == 120
        raise asyncio.CancelledError

    monkeypatch.setattr(main, "_get_auto_analysis_sweep_interval_seconds", lambda: 120)
    monkeypatch.setattr(main, "run_auto_analysis_sweep_once", sweep_mock)
    monkeypatch.setattr(main.asyncio, "sleep", stop_at_first_sleep)

    with pytest.raises(asyncio.CancelledError):
        await main.run_auto_analysis_sweep_loop()

    sweep_mock.assert_not_awaited()
    assert main.auto_analysis_sweep_state["next_run_at"]


@pytest.mark.asyncio
async def test_auto_sweep_worker_exception_updates_status(monkeypatch):
    def failing_worker():
        raise RuntimeError("sweep failed")

    monkeypatch.setenv("DTVP_CODE_ANALYSIS_URL", "http://example.com")
    monkeypatch.setenv("DTVP_AUTO_CODE_ANALYSIS_ENABLED", "true")
    monkeypatch.setattr(main, "_run_auto_analysis_sweep_worker", failing_worker)

    status = await main.run_auto_analysis_sweep_once("manual")

    assert status["running"] is False
    assert status["last_trigger"] == "manual"
    assert status["last_error"] == "sweep failed"
    assert status["last_finished_at"]


def test_auto_sweep_executor_shutdown_allows_recreation():
    first = main._get_auto_analysis_sweep_executor()
    assert first is main._auto_analysis_sweep_executor

    main.shutdown_auto_analysis_sweep_executor()
    assert main._auto_analysis_sweep_executor is None

    second = main._get_auto_analysis_sweep_executor()
    assert second is not first


def test_code_analysis_dashboard_status_disabled(client):
    with patch.dict(os.environ, {"DTVP_CODE_ANALYSIS_URL": ""}):
        response = client.get("/api/code-analysis/status")

    assert response.status_code == 200
    payload = response.json()
    assert payload["configured"] is False
    assert payload["overall_state"] == "disabled"
    assert payload["external"]["jobs"] == []
    assert payload["model_source"] == "not_reported"


def test_code_analysis_dashboard_status_reports_queue_and_external_state(client):
    item = main.analysis_queue.submit(
        vuln_id="CVE-2026-DASH",
        component_name="owned-service",
        submitted_by="testuser",
        source="automatic",
    )
    item.status = "running"
    item.job_id = "job-1"
    item.model = "gpt-queue"
    item.llm_backend = "openwebui"
    item.llm_provider = "OpenWebUI"
    item.logs = ["DTVP started scan"]
    item.progress = {
        "completed_steps": 2,
        "total_steps": 4,
        "percent": 50,
        "current_agent": "code_scanner",
        "current_step": "scan_code",
        "current_title": "Code Scan",
        "current_activity": "Scanning source",
        "active_agents": [
            {
                "step": "scan_code",
                "title": "Code Scan",
                "agent": "code_scanner",
                "activity": "Scanning source",
                "status": "running",
            }
        ],
    }
    queued = main.analysis_queue.submit(
        vuln_id="CVE-2026-QUEUE",
        component_name="owned-worker",
        submitted_by="testuser",
    )

    with patch.dict(os.environ, {"DTVP_CODE_ANALYSIS_URL": "http://example.com"}):
        with patch(
            "dtvp.main.CodeAnalysisClient.health",
            new=AsyncMock(
                return_value={
                    "status": "ok",
                    "model": "gpt-test",
                    "configuration": {
                        "service_name": "agentyzer",
                        "repositories": {
                            "workspace_dir": "/srv/agentyzer/repos",
                            "component_count": 7,
                        },
                    },
                    "backend": {
                        "llm": {
                            "provider": "OpenWebUI",
                            "backend": "openwebui",
                            "host": "http://openwebui",
                            "model": "gpt-health",
                        },
                        "jobs": {
                            "job_store": "memory",
                            "known_jobs": 2,
                            "max_concurrent_jobs": 2,
                            "running_jobs": 1,
                            "queued_jobs": 1,
                            "available_slots": 1,
                        },
                    },
                }
            ),
        ), patch(
            "dtvp.main.CodeAnalysisClient.list_jobs",
            new=AsyncMock(
                return_value={
                    "jobs": [
                        {
                            "job_id": "job-1",
                            "status": "running",
                            "created_at": "2026-01-01T00:00:00Z",
                            "progress": {
                                "completed_steps": 1,
                                "total_steps": 2,
                                "percent": 50,
                            },
                        }
                    ]
                }
            ),
        ):
            response = client.get("/api/code-analysis/status")

    assert response.status_code == 200
    payload = response.json()
    assert payload["overall_state"] == "running"
    assert payload["queue"]["dtvp_worker_busy"] is True
    assert payload["queue"]["waiting_for_slot"] is True
    assert payload["queue"]["capacity"] == 1
    assert payload["queue"]["available_slots"] == 0
    assert payload["queue"]["running_count"] == 1
    assert payload["queue"]["counts_by_status"]["running"] == 1
    assert payload["queue"]["counts_by_status"]["queued"] == 1
    assert payload["queue"]["active_item"]["queue_id"] == item.queue_id
    assert payload["queue"]["items"][1]["queue_id"] == queued.queue_id
    assert payload["active_agents"][0]["agent"] == "code_scanner"
    assert payload["external"]["busy"] is True
    assert payload["external"]["capacity"] == 2
    assert payload["external"]["running_jobs"] == 1
    assert payload["external"]["queued_jobs"] == 1
    assert payload["external"]["available_slots"] == 1
    assert payload["model"] == "gpt-queue"
    assert payload["model_source"] == "queue"
    assert payload["llm_backend"] == "openwebui"
    assert payload["llm_backend_source"] == "queue"
    assert payload["llm_provider"] == "OpenWebUI"
    assert payload["llm_provider_source"] == "queue"
    assert payload["queue"]["active_item"]["logs"] == ["DTVP started scan"]
    assert payload["external"]["configuration"]["service_name"] == "agentyzer"
    assert (
        payload["external"]["configuration"]["repositories"]["workspace_dir"]
        == "/srv/agentyzer/repos"
    )
    assert payload["external"]["backend"]["llm"]["host"] == "http://openwebui"


def test_code_analysis_dashboard_status_uses_configured_queue_capacity(client):
    running = main.analysis_queue.submit(
        vuln_id="CVE-2026-RUN",
        component_name="owned-service",
        submitted_by="testuser",
    )
    running.status = "running"
    queued = main.analysis_queue.submit(
        vuln_id="CVE-2026-QUEUED",
        component_name="owned-worker",
        submitted_by="testuser",
    )

    with patch.dict(
        os.environ,
        {
            "DTVP_CODE_ANALYSIS_URL": "",
            "DTVP_ANALYSIS_QUEUE_CAPACITY": "2",
        },
    ):
        response = client.get("/api/code-analysis/status")

    assert response.status_code == 200
    payload = response.json()
    assert payload["queue"]["capacity"] == 2
    assert payload["queue"]["running_count"] == 1
    assert payload["queue"]["available_slots"] == 1
    assert payload["queue"]["waiting_for_slot"] is False
    assert payload["queue"]["active_items"][0]["queue_id"] == running.queue_id
    assert payload["queue"]["items"][1]["queue_id"] == queued.queue_id


def test_code_analysis_dashboard_status_keeps_external_job_errors(client):
    with patch.dict(os.environ, {"DTVP_CODE_ANALYSIS_URL": "http://example.com"}):
        with patch(
            "dtvp.main.CodeAnalysisClient.health",
            new=AsyncMock(return_value={"status": "ok"}),
        ), patch(
            "dtvp.main.CodeAnalysisClient.list_jobs",
            new=AsyncMock(side_effect=RuntimeError("jobs unavailable")),
        ):
            response = client.get("/api/code-analysis/status")

    assert response.status_code == 200
    payload = response.json()
    assert payload["overall_state"] == "idle"
    assert payload["external"]["jobs"] == []
    assert "jobs unavailable" in payload["external"]["jobs_error"]


def test_code_analysis_dashboard_status_times_out_slow_external_health(client):
    async def slow_health():
        await asyncio.sleep(1)
        return {"status": "ok"}

    with patch.dict(
        os.environ,
        {
            "DTVP_CODE_ANALYSIS_URL": "http://example.com",
            "DTVP_CODE_ANALYSIS_STATUS_TIMEOUT_SECONDS": "0.1",
        },
    ):
        with patch(
            "dtvp.main.CodeAnalysisClient.health",
            new=AsyncMock(side_effect=slow_health),
        ), patch(
            "dtvp.main.CodeAnalysisClient.list_jobs",
            new=AsyncMock(return_value={"jobs": []}),
        ):
            response = client.get("/api/code-analysis/status")

    assert response.status_code == 200
    payload = response.json()
    assert payload["overall_state"] == "unavailable"
    assert payload["external"]["jobs"] == []
    assert "Timed out after 0.1s" in payload["external"]["health_error"]
    assert payload["external"]["jobs_error"] is None


def test_analysis_queue_submit_list_get_cancel(client):
    response = client.post(
        "/api/analysis-queue/submit",
        json={
            "vuln_id": "CVE-2024-2000",
            "component_name": "libA",
            "project_name": "ExampleApp",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "user_guidance": "Review this component",
        },
    )
    assert response.status_code == 200
    payload = response.json()
    queue_id = payload["queue_id"]
    assert payload["status"] == "queued"
    assert payload["component_name"] == "libA"
    assert payload["project_name"] == "ExampleApp"

    list_response = client.get("/api/analysis-queue")
    assert list_response.status_code == 200
    assert any(item["queue_id"] == queue_id for item in list_response.json())

    get_response = client.get(f"/api/analysis-queue/{queue_id}")
    assert get_response.status_code == 200
    assert get_response.json()["queue_id"] == queue_id

    delete_response = client.delete(f"/api/analysis-queue/{queue_id}")
    assert delete_response.status_code == 200
    assert delete_response.json() == {"status": "cancelled"}

    list_after_cancel = client.get("/api/analysis-queue")
    assert all(item["queue_id"] != queue_id for item in list_after_cancel.json())


def test_analysis_queue_and_results_are_scoped_for_analysts(client):
    owned = main.analysis_queue.submit(
        vuln_id="CVE-2026-OWNED",
        component_name="owned-component",
        submitted_by="testuser",
    )
    other = main.analysis_queue.submit(
        vuln_id="CVE-2026-OTHER",
        component_name="other-component",
        submitted_by="other-user",
    )
    for item in (owned, other):
        item.status = "running"
        main.analysis_queue._finish_item(
            item,
            status="completed",
            result={
                "assessment": {
                    "affected": False,
                    "verdict": "Not Affected",
                    "confidence": "High",
                    "exposure": "none",
                    "summary": "No vulnerable path.",
                    "reasoning": "No reachable code.",
                },
                "steps": [],
            },
        )

    with patch("dtvp.main.get_user_role", return_value="ANALYST"):
        queue_response = client.get("/api/analysis-queue")
        result_response = client.get(
            "/api/code-analysis/results?vuln_id=CVE-2026-OWNED"
        )
        status_response = client.get("/api/code-analysis/status")
        other_queue_response = client.get(f"/api/analysis-queue/{other.queue_id}")
        other_result_response = client.get(
            f"/api/code-analysis/results/{other.queue_id}"
        )
        other_cancel_response = client.delete(
            f"/api/analysis-queue/{other.queue_id}"
        )

    assert [item["queue_id"] for item in queue_response.json()] == [owned.queue_id]
    assert [item["analysis_run_id"] for item in result_response.json()] == [
        owned.queue_id
    ]
    status = status_response.json()
    assert [item["queue_id"] for item in status["queue"]["items"]] == [
        owned.queue_id
    ]
    assert "path" not in status["result_cache"]
    assert "legacy_json_path" not in status["result_cache"]
    assert other_queue_response.status_code == 404
    assert other_result_response.status_code == 404
    assert other_cancel_response.status_code == 404


def test_global_code_analysis_controls_require_reviewer(client):
    with patch("dtvp.main.get_user_role", return_value="ANALYST"):
        assert client.get("/api/code-analysis/health").status_code == 403
        assert client.get("/api/code-analysis/prompts").status_code == 403
        assert client.post("/api/code-analysis/auto-sweep/run").status_code == 403
        assert client.post("/api/analysis-queue/clear").status_code == 403
        assert client.post("/api/analysis-queue/cancel-queued").status_code == 403


def test_analysis_queue_submit_accepts_benchmark_source(client):
    response = client.post(
        "/api/analysis-queue/submit",
        json={
            "vuln_id": "CVE-2026-BENCH-SOURCE",
            "component_name": "owned-api",
            "project_name": "ExampleApp",
            "source": "benchmark",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["source"] == "benchmark"
    item = main.analysis_queue.get(payload["queue_id"])
    assert item.source == "benchmark"


def test_analysis_queue_submit_appends_component_guidance(client, monkeypatch):
    monkeypatch.setattr(
        main,
        "load_auto_analysis_guidance",
        lambda: {
            "components": {
                "gehc-vp6-keycloak": {
                    "guidance": [
                        "This project extends Keycloak.",
                        "If the extension is not affected, still consider whether upstream Keycloak itself is vulnerable.",
                    ]
                }
            }
        },
    )

    response = client.post(
        "/api/analysis-queue/submit",
        json={
            "vuln_id": "CVE-2026-KEYCLOAK",
            "component_name": "gehc-vp6-keycloak",
            "project_name": "ExampleApp",
            "user_guidance": "Manual reviewer note.",
        },
    )

    assert response.status_code == 200
    item = main.analysis_queue.get(response.json()["queue_id"])
    assert item.user_guidance.startswith("Manual reviewer note.")
    assert "scan target gehc-vp6-keycloak" in item.user_guidance
    assert "This project extends Keycloak." in item.user_guidance
    assert "upstream Keycloak itself is vulnerable" in item.user_guidance


def test_completed_analysis_queue_item_persists_result_history(client):
    item = main.analysis_queue.submit(
        vuln_id="CVE-2026-PERSIST",
        component_name="owned-api",
        project_name="ExampleApp",
        submitted_by="testuser",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    )
    item.status = "running"
    item.job_id = "job-persist"
    result = {
        "assessment": {
            "affected": False,
            "verdict": "Not Affected",
            "confidence": "High",
            "exposure": "none",
            "analysis": "NOT_AFFECTED",
            "justification": "CODE_NOT_PRESENT",
            "response": "NOT_SET",
            "summary": "No vulnerable code path was found.",
            "reasoning": "The extension does not include the affected package.",
            "details": "Detailed evidence",
            "adjusted_cvss": {
                "original_score": 9.8,
                "adjusted_score": 0.0,
                "original_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "adjusted_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                "reasons": ["code not present"],
                "summary": "9.8 -> 0.0",
            },
        },
        "steps": [
            {
                "step": "scan_code",
                "title": "Code scan",
                "status": "pass",
                "findings": {},
                "evidence": ["No imports found"],
            }
        ],
        "versions_checked": ["1.0.0"],
        "llm_conversation": [
            {
                "messages": [
                    {"role": "system", "content": "System prompt"},
                    {"role": "user", "content": "ANALYST GUIDANCE:\nTeam note"},
                ],
                "response": {"role": "assistant", "content": "Model answer"},
                "status": "completed",
            }
        ],
    }

    main.analysis_queue._finish_item(item, status="completed", result=result)

    response = client.get(
        "/api/projects/ExampleApp/vulnerabilities/CVE-2026-PERSIST/analysis-results"
    )
    assert response.status_code == 200
    payload = response.json()
    assert len(payload) == 1
    assert payload[0]["analysis_run_id"] == item.queue_id
    assert payload[0]["job_id"] == "job-persist"
    assert payload[0]["summary"]["verdict"] == "Not Affected"
    assert "result" not in payload[0]

    detail_response = client.get(f"/api/code-analysis/results/{item.queue_id}")
    assert detail_response.status_code == 200
    detail = detail_response.json()
    assert detail["result"]["assessment"]["summary"] == "No vulnerable code path was found."
    assert detail["result"]["llm_conversation"][0]["messages"][1]["content"].endswith("Team note")
    assert detail["compact_context"]["target"]["component_name"] == "owned-api"
    assert detail["user_guidance_redacted"] is False


def test_code_analysis_benchmark_result_delegates_to_agentyzer(client):
    item = main.analysis_queue.submit(
        vuln_id="CVE-2026-BENCH",
        component_name="owned-api",
        project_name="ExampleApp",
        submitted_by="testuser",
        source="benchmark",
    )
    item.status = "running"
    item.job_id = "job-benchmark"
    result = {
        "assessment": {
            "affected": False,
            "verdict": "Not Affected",
            "confidence": "High",
            "exposure": "none",
            "analysis": "NOT_AFFECTED",
            "justification": "CODE_NOT_PRESENT",
            "response": "NOT_SET",
            "summary": "No vulnerable code path was found.",
            "reasoning": "The vulnerable package is not present in the analyzed source tree.",
            "details": "No imports found.",
            "adjusted_cvss": {
                "original_score": 9.8,
                "adjusted_score": 0.0,
                "original_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "adjusted_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                "reasons": ["code not present"],
                "summary": "9.8 -> 0.0",
            },
        },
        "steps": [],
        "versions_checked": ["1.0.0"],
    }
    main.analysis_queue._finish_item(item, status="completed", result=result)

    agentyzer_payload = {
        "schema_version": "agentyzer.benchmark-comparison/v1",
        "comparison_method": "agentyzer_probabilistic",
        "evaluator": {"provider": "agentyzer", "probabilistic": True},
        "rating": {
            "score": 4,
            "max_score": 5,
            "grade": "B",
            "label": "Good match",
            "tone": "cyan",
            "confidence": 0.8,
        },
        "human": {"state": "NOT_AFFECTED"},
        "automated": {"state": "NOT_AFFECTED"},
        "deltas": {"state_match": True},
        "findings": [],
        "recommendation": "Aligned.",
    }

    with patch.dict(os.environ, {"DTVP_CODE_ANALYSIS_URL": "http://example.com"}):
        with patch(
            "dtvp.main.CodeAnalysisClient.compare_benchmark",
            new=AsyncMock(return_value=agentyzer_payload),
        ) as compare_mock:
            response = client.post(
                f"/api/code-analysis/results/{item.queue_id}/benchmark",
                json={
                    "current_state": "NOT_AFFECTED",
                    "current_justification": "CODE_NOT_PRESENT",
                    "current_details": "No vulnerable code path was found.",
                    "current_cvss_score": 0.0,
                },
            )

    assert response.status_code == 200
    assert response.json()["comparison_method"] == "agentyzer_probabilistic"
    compare_mock.assert_awaited_once()
    sent_benchmark = compare_mock.await_args.args[0]
    assert sent_benchmark["comparison_method"] == "deterministic_fallback"
    assert sent_benchmark["human"]["state"] == "NOT_AFFECTED"
    assert sent_benchmark["automated"]["state"] == "NOT_AFFECTED"


def test_code_analysis_benchmark_result_falls_back_when_agentyzer_unavailable(client):
    item = main.analysis_queue.submit(
        vuln_id="CVE-2026-BENCH-FALLBACK",
        component_name="owned-api",
        project_name="ExampleApp",
        submitted_by="testuser",
        source="benchmark",
    )
    item.status = "running"
    item.job_id = "job-benchmark-fallback"
    main.analysis_queue._finish_item(
        item,
        status="completed",
        result={
            "assessment": {
                "affected": False,
                "verdict": "Not Affected",
                "confidence": "High",
                "exposure": "none",
                "analysis": "NOT_AFFECTED",
                "justification": "CODE_NOT_PRESENT",
                "summary": "No vulnerable code path was found.",
                "reasoning": "The vulnerable package is not present in the analyzed source tree.",
                "details": "No imports found.",
            },
            "steps": [],
            "versions_checked": ["1.0.0"],
        },
    )

    with patch.dict(os.environ, {"DTVP_CODE_ANALYSIS_URL": "http://example.com"}):
        with patch(
            "dtvp.main.CodeAnalysisClient.compare_benchmark",
            new=AsyncMock(side_effect=RuntimeError("offline")),
        ) as compare_mock:
            response = client.post(
                f"/api/code-analysis/results/{item.queue_id}/benchmark",
                json={
                    "current_state": "NOT_AFFECTED",
                    "current_justification": "CODE_NOT_PRESENT",
                    "current_details": "No vulnerable code path was found.",
                    "current_cvss_score": 0.0,
                },
            )

    assert response.status_code == 200
    payload = response.json()
    assert payload["comparison_method"] == "deterministic_fallback"
    assert payload["evaluator"] == {
        "provider": "dtvp",
        "probabilistic": False,
        "available": False,
        "reason": "Agentyzer benchmark comparison unavailable: offline",
    }
    assert payload["rating"]["max_score"] == 5
    assert payload["human"]["state"] == "NOT_AFFECTED"
    assert payload["automated"]["state"] == "NOT_AFFECTED"
    compare_mock.assert_awaited_once()


def test_code_analysis_result_can_be_deleted_from_history(client):
    item = main.analysis_queue.submit(
        vuln_id="CVE-2026-DELETE",
        component_name="owned-api",
        project_name="ExampleApp",
        submitted_by="testuser",
    )
    item.status = "running"
    main.analysis_queue._finish_item(
        item,
        status="completed",
        result={
            "assessment": {
                "affected": False,
                "verdict": "Not Affected",
                "confidence": "High",
                "exposure": "none",
                "summary": "No vulnerable path.",
                "reasoning": "No path.",
            },
            "steps": [],
        },
    )

    delete_response = client.delete(f"/api/code-analysis/results/{item.queue_id}")
    assert delete_response.status_code == 200
    assert delete_response.json() == {
        "status": "removed",
        "analysis_run_id": item.queue_id,
    }

    detail_response = client.get(f"/api/code-analysis/results/{item.queue_id}")
    assert detail_response.status_code == 404

    list_response = client.get(
        "/api/projects/ExampleApp/vulnerabilities/CVE-2026-DELETE/analysis-results"
    )
    assert list_response.status_code == 200
    assert list_response.json() == []

    second_delete = client.delete(f"/api/code-analysis/results/{item.queue_id}")
    assert second_delete.status_code == 404


def test_code_analysis_result_store_can_redact_guidance(client, monkeypatch):
    monkeypatch.setenv("DTVP_CODE_ANALYSIS_RESULTS_STORE_GUIDANCE", "false")
    item = main.analysis_queue.submit(
        vuln_id="CVE-2026-REDACT",
        component_name="owned-api",
        project_name="ExampleApp",
        submitted_by="testuser",
        user_guidance="Sensitive reviewer context",
        follow_up_user_guidance="Sensitive follow-up note",
    )
    item.status = "running"
    main.analysis_queue._finish_item(
        item,
        status="completed",
        result={
            "assessment": {
                "affected": False,
                "verdict": "Not Affected",
                "confidence": "High",
                "exposure": "none",
                "summary": "No vulnerable path.",
                "reasoning": "No path.",
            },
            "steps": [],
            "llm_conversation": [
                {
                    "messages": [
                        {
                            "role": "user",
                            "content": "Sensitive reviewer context",
                        }
                    ],
                    "response": {
                        "role": "assistant",
                        "content": "Sensitive model response",
                    },
                }
            ],
        },
    )

    response = client.get(f"/api/code-analysis/results/{item.queue_id}")
    assert response.status_code == 200
    detail = response.json()
    assert detail["user_guidance"] is None
    assert detail["follow_up_user_guidance"] is None
    assert detail["user_guidance_redacted"] is True
    assert "llm_conversation" not in detail["result"]


def test_code_analysis_dashboard_status_reports_result_cache_policy(client):
    with patch.dict(os.environ, {"DTVP_CODE_ANALYSIS_URL": ""}):
        response = client.get("/api/code-analysis/status")

    assert response.status_code == 200
    cache_status = response.json()["result_cache"]
    assert cache_status["record_count"] == 0
    assert cache_status["max_records"] >= 1
    assert cache_status["store_guidance"] is True


def test_code_analysis_prompt_endpoint_proxies_analyzer(client):
    with patch.dict(os.environ, {"DTVP_CODE_ANALYSIS_URL": "http://example.com"}):
        with patch(
            "dtvp.main.CodeAnalysisClient.get_prompts",
            new=AsyncMock(
                return_value={
                    "schema_version": "agentyzer.prompts/v1",
                    "bundles": [
                        {
                            "bundle": "verdict",
                            "values": {"system": "You are a security reviewer."},
                        }
                    ],
                }
            ),
        ) as prompt_mock:
            response = client.get(
                "/api/code-analysis/prompts",
                params={"include_values": "true", "system_only": "true"},
            )

    assert response.status_code == 200
    assert response.json()["bundles"][0]["values"]["system"].startswith("You are")
    prompt_mock.assert_awaited_once_with(include_values=True, system_only=True)


def test_analysis_queue_follow_up_uses_persisted_parent_context(client):
    item = main.analysis_queue.submit(
        vuln_id="CVE-2026-FOLLOW",
        component_name="keycloak-extension",
        project_name="ExampleApp",
        submitted_by="testuser",
    )
    item.status = "running"
    item.job_id = "job-parent"
    main.analysis_queue._finish_item(
        item,
        status="completed",
        result={
            "assessment": {
                "affected": False,
                "verdict": "Not Affected",
                "confidence": "Medium",
                "exposure": "transitive",
                "analysis": "NOT_AFFECTED",
                "justification": "CODE_NOT_REACHABLE",
                "response": "NOT_SET",
                "summary": "Extension is not affected.",
                "reasoning": "Only extension-specific code was checked.",
                "details": "Prior analysis details",
            },
            "steps": [],
        },
    )

    response = client.post(
        "/api/analysis-queue/follow-up",
        json={
            "parent_run_id": item.queue_id,
            "question": "Is Keycloak itself vulnerable in this deployment?",
            "component_name": "keycloak",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["source"] == "follow-up"
    assert payload["parent_run_id"] == item.queue_id
    assert payload["parent_job_id"] == "job-parent"
    assert payload["component_name"] == "keycloak"
    assert payload["follow_up_question"] == "Is Keycloak itself vulnerable in this deployment?"
    assert payload["follow_up_user_guidance"] is None
    assert "Compact prior context" in payload["user_guidance"]
    assert "Extension is not affected" in payload["user_guidance"]


def test_analysis_queue_cancel_completed_removes_item(client):
    item = main.analysis_queue.submit(
        vuln_id="CVE-2024-2001",
        component_name="libB",
        submitted_by="testuser",
    )
    item.status = "completed"

    response = client.delete(f"/api/analysis-queue/{item.queue_id}")
    assert response.status_code == 200
    assert response.json() == {"status": "removed"}
    assert main.analysis_queue.get(item.queue_id) is None


def test_analysis_queue_cancel_running_without_job_requests_abort(client):
    item = main.analysis_queue.submit(
        vuln_id="CVE-2024-2002",
        component_name="libC",
        submitted_by="testuser",
    )
    item.status = "running"

    response = client.delete(f"/api/analysis-queue/{item.queue_id}")
    assert response.status_code == 200
    assert response.json() == {"status": "abort_requested"}
    assert item.abort_requested is True


def test_analysis_queue_abort_running_job_success(client):
    item = main.analysis_queue.submit(
        vuln_id="CVE-2024-2005",
        component_name="libAbort",
        submitted_by="testuser",
    )
    item.status = "running"
    item.job_id = "job-abort"

    with patch.dict(os.environ, {"DTVP_CODE_ANALYSIS_URL": "http://example.com"}):
        with patch(
            "dtvp.main.CodeAnalysisClient.delete_job",
            new=AsyncMock(return_value=None),
        ) as delete_mock:
            response = client.delete(f"/api/analysis-queue/{item.queue_id}")

    assert response.status_code == 200
    assert response.json() == {"status": "cancelled"}
    assert item.status == "cancelled"
    assert item.finished_at
    delete_mock.assert_awaited_once_with("job-abort")


def test_analysis_queue_abort_running_job_refusal_returns_conflict(client):
    item = main.analysis_queue.submit(
        vuln_id="CVE-2024-2006",
        component_name="libAbortRefused",
        submitted_by="testuser",
    )
    item.status = "running"
    item.job_id = "job-refused"

    with patch.dict(os.environ, {"DTVP_CODE_ANALYSIS_URL": "http://example.com"}):
        with patch(
            "dtvp.main.CodeAnalysisClient.delete_job",
            new=AsyncMock(side_effect=RuntimeError("still running")),
        ):
            response = client.delete(f"/api/analysis-queue/{item.queue_id}")

    assert response.status_code == 409
    assert "refused abort" in response.json()["detail"]
    assert item.status == "running"
    assert item.abort_requested is False
    assert item.abort_error == "still running"


def test_analysis_queue_cancel_missing_returns_404(client):
    response = client.delete("/api/analysis-queue/unknown")
    assert response.status_code == 404


def test_analysis_queue_bulk_cancel_and_clear(client):
    queued_one = main.analysis_queue.submit(
        vuln_id="CVE-2024-BULK-1",
        component_name="libQueuedOne",
        submitted_by="testuser",
    )
    queued_two = main.analysis_queue.submit(
        vuln_id="CVE-2024-BULK-2",
        component_name="libQueuedTwo",
        submitted_by="testuser",
    )
    completed = main.analysis_queue.submit(
        vuln_id="CVE-2024-BULK-3",
        component_name="libCompleted",
        submitted_by="testuser",
    )
    completed.status = "completed"

    cancel_response = client.post("/api/analysis-queue/cancel-queued")
    assert cancel_response.status_code == 200
    assert cancel_response.json()["cancelled"] == 2
    assert queued_one.status == "cancelled"
    assert queued_two.status == "cancelled"

    clear_response = client.post("/api/analysis-queue/clear")
    assert clear_response.status_code == 200
    assert clear_response.json()["removed"] == 3
    assert main.analysis_queue.get(completed.queue_id) is None


def test_analysis_queue_submit_once_deduplicates_existing_items(client):
    first, created = main.analysis_queue.submit_once(
        vuln_id="CVE-2026-DEDUPE",
        component_name="libA",
        submitted_by="dtvp-auto-analysis",
        source="automatic",
    )
    second, duplicate_created = main.analysis_queue.submit_once(
        vuln_id="cve-2026-dedupe",
        component_name="LIBA",
        submitted_by="dtvp-auto-analysis",
        source="automatic",
    )

    assert created is True
    assert duplicate_created is False
    assert second is first
    assert first.source == "automatic"

    first.status = "completed"
    completed_duplicate, completed_created = main.analysis_queue.submit_once(
        vuln_id="CVE-2026-DEDUPE",
        component_name="libA",
        submitted_by="dtvp-auto-analysis",
        source="automatic",
    )

    assert completed_created is False
    assert completed_duplicate is first


@pytest.mark.asyncio
async def test_analysis_queue_wait_for_work_keeps_existing_wake_signal(client):
    main.analysis_queue._event.set()

    await asyncio.wait_for(main.analysis_queue._wait_for_work(), timeout=0.1)

    assert not main.analysis_queue._event.is_set()


@pytest.mark.asyncio
async def test_analysis_queue_worker_starts_up_to_configured_capacity():
    class FakeLogger:
        def info(self, *_args, **_kwargs):
            return None

        def exception(self, *_args, **_kwargs):
            return None

    class FakeItem:
        def __init__(self, queue_id):
            self.queue_id = queue_id
            self.vuln_id = f"CVE-{queue_id}"
            self.component_name = f"component-{queue_id}"
            self.status = "queued"

    items = [FakeItem("1"), FakeItem("2"), FakeItem("3")]
    both_started = asyncio.Event()
    release = asyncio.Event()
    running = True
    started: list[str] = []

    def get_next_item():
        return next((item for item in items if item.status == "queued"), None)

    def start_item(item):
        item.status = "running"
        started.append(item.queue_id)
        if len(started) == 2:
            both_started.set()

    async def process_item(item):
        await both_started.wait()
        await release.wait()
        finish_item(item, status="completed")

    def finish_item(item, *, status, **_kwargs):
        item.status = status

    async def wait_for_work():
        await asyncio.sleep(0.01)

    def is_running():
        return running

    worker_task = asyncio.create_task(
        run_analysis_queue_worker(
            AnalysisQueueRuntimeDeps(logger=FakeLogger(), sleep=asyncio.sleep),
            is_running,
            prune_finished=lambda: 0,
            get_next_item=get_next_item,
            wait_for_work=wait_for_work,
            start_item=start_item,
            process_item=process_item,
            finish_item=finish_item,
            get_capacity=lambda: 2,
        )
    )
    await asyncio.wait_for(both_started.wait(), timeout=1)

    running = False
    release.set()
    await asyncio.wait_for(worker_task, timeout=1)

    assert started == ["1", "2"]
    assert items[0].status == "completed"
    assert items[1].status == "completed"
    assert items[2].status == "queued"


@pytest.mark.asyncio
async def test_analysis_queue_worker_passes_user_guidance_to_client(monkeypatch):
    captured: dict[str, object] = {}

    class FakeClient:
        def __init__(self, _settings, *, owner=None):
            self._settings = _settings
            captured["owner"] = owner

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            return None

        async def start_assessment(self, **kwargs):
            captured.update(kwargs)
            return {"job_id": "job-1"}

        async def get_job_status(self, _job_id):
            return {
                "status": "completed",
                "logs": ["Analyzer started scan"],
                "progress": {
                    "completed_steps": 1,
                    "total_steps": 2,
                    "percent": 50,
                    "current_agent": "code_scanner",
                    "current_step": "scan_code",
                    "current_title": "Code Scan",
                    "current_activity": "Scanning source",
                    "last_updated_at": "2026-07-02T10:00:00Z",
                    "active_agents": [
                        {
                            "step": "scan_code",
                            "title": "Code Scan",
                            "agent": "code_scanner",
                            "activity": "Scanning source",
                            "status": "running",
                        }
                    ],
                },
            }

        async def get_job_result(self, _job_id):
            return {"assessment": {"summary": "done"}, "steps": []}

    item = main.analysis_queue.submit(
        vuln_id="GHSA-queue-test",
        component_name="libA",
        submitted_by="testuser",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        user_guidance="Check GHSA metadata gaps",
        affected_product_versions=["1.0.0", "1.1.0"],
    )

    completed: dict[str, object] = {}

    def finish_item(_item, **kwargs):
        completed.update(kwargs)

    class FakeSettings:
        enabled = True
        DTVP_CODE_ANALYSIS_MODEL = "gpt-config"
        DTVP_CODE_ANALYSIS_LLM_BACKEND = "openwebui"
        DTVP_CODE_ANALYSIS_LLM_PROVIDER = "OpenWebUI"

    deps = AnalysisQueueServiceDeps(
        get_code_analysis_settings_cls=lambda: FakeSettings,
        get_code_analysis_client_cls=lambda: FakeClient,
        code_analysis_not_configured_detail="not configured",
        sleep=AsyncMock(),
    )

    await process_analysis_queue_item(deps, item, finish_item)

    assert captured["user_guidance"] == "Check GHSA metadata gaps"
    assert captured["owner"] == "testuser"
    assert captured["affected_product_versions"] == ["1.0.0", "1.1.0"]
    assert captured["model"] == "gpt-config"
    assert captured["llm_backend"] == "openwebui"
    assert captured["llm_provider"] == "OpenWebUI"
    assert item.model == "gpt-config"
    assert any("Analyzer started scan" in line for line in item.logs)
    assert any("Scanning source" in line for line in item.logs)
    assert completed["status"] == "completed"


@pytest.mark.asyncio
async def test_analysis_queue_worker_sends_lean_guidance_to_native_follow_up(
    monkeypatch,
):
    captured: dict[str, object] = {}

    class FakeClient:
        def __init__(self, _settings, *, owner=None):
            self._settings = _settings
            captured["owner"] = owner

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            return None

        async def start_follow_up(self, job_id, **kwargs):
            captured["job_id"] = job_id
            captured.update(kwargs)
            return {"job_id": "job-follow-up"}

        async def start_assessment(self, **_kwargs):
            raise AssertionError("native follow-up should be used")

        async def get_job_status(self, _job_id):
            return {"status": "completed"}

        async def get_job_result(self, _job_id):
            return {"assessment": {"summary": "done"}, "steps": []}

    item = main.analysis_queue.submit(
        vuln_id="CVE-2026-FOLLOW",
        component_name="keycloak",
        submitted_by="testuser",
        user_guidance="DTVP compact prior context that must only be used for fallback",
        parent_job_id="parent-job",
        follow_up_question="Is Keycloak itself vulnerable?",
        follow_up_user_guidance="Reviewer asks about upstream Keycloak itself.",
        source="follow-up",
    )

    completed: dict[str, object] = {}

    def finish_item(_item, **kwargs):
        completed.update(kwargs)

    class FakeSettings:
        enabled = True
        DTVP_CODE_ANALYSIS_MODEL = ""
        DTVP_CODE_ANALYSIS_LLM_BACKEND = ""
        DTVP_CODE_ANALYSIS_LLM_PROVIDER = ""

    deps = AnalysisQueueServiceDeps(
        get_code_analysis_settings_cls=lambda: FakeSettings,
        get_code_analysis_client_cls=lambda: FakeClient,
        code_analysis_not_configured_detail="not configured",
        sleep=AsyncMock(),
    )

    await process_analysis_queue_item(deps, item, finish_item)

    assert captured["job_id"] == "parent-job"
    assert captured["owner"] == "testuser"
    assert captured["question"] == "Is Keycloak itself vulnerable?"
    assert captured["user_guidance"] == "Reviewer asks about upstream Keycloak itself."
    assert "DTVP compact prior context" not in str(captured)
    assert any("analyzer-native parent context" in line for line in item.logs)
    assert completed["status"] == "completed"


@pytest.mark.asyncio
async def test_analysis_queue_worker_treats_analyzer_cancelled_as_terminal(monkeypatch):
    class FakeClient:
        def __init__(self, _settings, *, owner=None):
            self._settings = _settings
            self.owner = owner

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            return None

        async def start_assessment(self, **_kwargs):
            return {"job_id": "job-cancelled"}

        async def get_job_status(self, _job_id):
            return {
                "status": "cancelled",
                "error": "Cancelled by analyzer.",
                "logs": ["Analyzer cancelled scan"],
            }

    class FakeSettings:
        enabled = True

    deps = AnalysisQueueServiceDeps(
        get_code_analysis_settings_cls=lambda: FakeSettings,
        get_code_analysis_client_cls=lambda: FakeClient,
        code_analysis_not_configured_detail="not configured",
        sleep=AsyncMock(),
    )
    item = main.analysis_queue.submit(
        vuln_id="CVE-2026-CANCELLED",
        component_name="libCancelled",
        submitted_by="testuser",
    )
    completed: dict[str, object] = {}

    def finish_item(_item, **kwargs):
        completed.update(kwargs)

    await process_analysis_queue_item(deps, item, finish_item)

    assert completed["status"] == "cancelled"
    assert completed["error"] == "Cancelled by analyzer."
    assert any("Analyzer cancelled scan" in line for line in item.logs)


def test_analysis_queue_prune_finished_removes_expired_terminal_items():
    expired = main.analysis_queue.submit(
        vuln_id="CVE-2024-3000",
        component_name="libExpired",
        submitted_by="testuser",
    )

    fresh = main.analysis_queue.submit(
        vuln_id="CVE-2024-3001",
        component_name="libFresh",
        submitted_by="testuser",
    )

    running = main.analysis_queue.submit(
        vuln_id="CVE-2024-3002",
        component_name="libRunning",
        submitted_by="testuser",
    )
    running.status = "running"

    cancelled = main.analysis_queue.submit(
        vuln_id="CVE-2024-3003",
        component_name="libCancelled",
        submitted_by="testuser",
    )

    expired.status = "completed"
    expired.finished_at = datetime.fromtimestamp(1000, UTC).isoformat()

    fresh.status = "failed"
    fresh.finished_at = datetime.fromtimestamp(4500, UTC).isoformat()

    cancelled.status = "cancelled"
    cancelled.finished_at = datetime.fromtimestamp(1200, UTC).isoformat()

    with patch.dict(
        os.environ, {"DTVP_ANALYSIS_QUEUE_TTL_SECONDS": "3600"}, clear=False
    ):
        removed = main.analysis_queue.prune_finished(now=5000)

    assert removed == 2
    assert expired.queue_id not in main.analysis_queue._items
    assert cancelled.queue_id not in main.analysis_queue._items
    assert main.analysis_queue._items[fresh.queue_id] is fresh
    assert main.analysis_queue._items[running.queue_id] is running


def test_analysis_queue_list_prunes_expired_finished_items(client):
    item = main.analysis_queue.submit(
        vuln_id="CVE-2024-3004",
        component_name="libPruned",
        submitted_by="testuser",
    )
    item.status = "completed"
    item.finished_at = datetime.fromtimestamp(1000, UTC).isoformat()

    with patch.dict(
        os.environ, {"DTVP_ANALYSIS_QUEUE_TTL_SECONDS": "3600"}, clear=False
    ):
        with patch("dtvp.main.datetime") as mock_datetime:
            mock_datetime.now.return_value = datetime.fromtimestamp(5000, UTC)
            mock_datetime.fromisoformat.side_effect = datetime.fromisoformat
            response = client.get("/api/analysis-queue")

    assert response.status_code == 200
    assert response.json() == []
    assert main.analysis_queue.get(item.queue_id) is None
