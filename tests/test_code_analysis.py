import asyncio
import os
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import dtvp.agentizer_integration as agentizer
import dtvp.code_analysis_integration as code_analysis
from dtvp import main
from dtvp.analysis_queue_services import (
    AnalysisQueueServiceDeps,
    process_analysis_queue_item,
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

    dummy_client = MagicMock()
    dummy_client.get = AsyncMock(
        side_effect=[
            DummyResponse({"health": "ok"}),
            DummyResponse({"status": "running"}),
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

    assert await client.health() == {"health": "ok"}
    assert await client.start_assessment(
        vuln_id="CVE-2024-1000",
        component_name="libA",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        user_guidance="Please review",
        focus_path="root>libA",
        dependency_paths=[["root", "libA"]],
        debug=True,
    ) == {"job_id": "job-1"}

    assert await client.start_assessment_sync(
        vuln_id="CVE-2024-1001",
        component_name="libB",
        debug=False,
    ) == {"job_id": "job-2"}

    assert await client.get_job_status("job-1") == {"status": "running"}
    assert await client.get_job_result("job-1") == {"result": "done"}
    assert await client.delete_job("job-1") is None
    await client.close()

    assert dummy_client.post.call_count == 2
    assert dummy_client.post.call_args_list[1].kwargs["params"] == {"sync": "true"}
    assert (
        dummy_client.post.call_args_list[0].kwargs["json"]["user_guidance"]
        == "Please review"
    )
    dummy_client.aclose.assert_awaited_once()


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
    class FakeDTClient:
        def __init__(self, *_args, **_kwargs):
            pass

        async def __aenter__(self):
            return object()

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            return None

    with patch.dict(
        os.environ,
        {
            "DTVP_CODE_ANALYSIS_URL": "http://example.com",
            "DTVP_AUTO_CODE_ANALYSIS_ENABLED": "true",
            "DTVP_AUTO_CODE_ANALYSIS_SWEEP_SECONDS": "120",
        },
    ):
        with patch("dtvp.main.DTClient", FakeDTClient), patch(
            "dtvp.main.queue_existing_open_vulnerabilities_for_analysis_impl",
            new=AsyncMock(return_value=2),
        ) as sweep_mock:
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
    assert payload["running"] is False
    assert payload["last_trigger"] == "manual"
    assert payload["last_queued_count"] == 2
    assert payload["last_started_at"]
    assert payload["last_finished_at"]
    sweep_mock.assert_awaited_once()


def test_analysis_queue_submit_list_get_cancel(client):
    response = client.post(
        "/api/analysis-queue/submit",
        json={
            "vuln_id": "CVE-2024-2000",
            "component_name": "libA",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "user_guidance": "Review this component",
        },
    )
    assert response.status_code == 200
    payload = response.json()
    queue_id = payload["queue_id"]
    assert payload["status"] == "queued"
    assert payload["component_name"] == "libA"

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


def test_analysis_queue_cancel_running_returns_conflict(client):
    item = main.analysis_queue.submit(
        vuln_id="CVE-2024-2002",
        component_name="libC",
        submitted_by="testuser",
    )
    item.status = "running"

    response = client.delete(f"/api/analysis-queue/{item.queue_id}")
    assert response.status_code == 409


def test_analysis_queue_cancel_missing_returns_404(client):
    response = client.delete("/api/analysis-queue/unknown")
    assert response.status_code == 404


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
async def test_analysis_queue_worker_passes_user_guidance_to_client(monkeypatch):
    captured: dict[str, str] = {}

    class FakeClient:
        def __init__(self, _settings):
            self._settings = _settings

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            return None

        async def start_assessment(self, **kwargs):
            captured.update(kwargs)
            return {"job_id": "job-1"}

        async def get_job_status(self, _job_id):
            return {"status": "completed"}

        async def get_job_result(self, _job_id):
            return {"assessment": {"summary": "done"}, "steps": []}

    item = main.analysis_queue.submit(
        vuln_id="GHSA-queue-test",
        component_name="libA",
        submitted_by="testuser",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        user_guidance="Check GHSA metadata gaps",
    )

    completed: dict[str, object] = {}

    def finish_item(_item, **kwargs):
        completed.update(kwargs)

    deps = AnalysisQueueServiceDeps(
        get_code_analysis_settings_cls=lambda: (
            lambda: type("Settings", (), {"enabled": True})()
        ),
        get_code_analysis_client_cls=lambda: FakeClient,
        code_analysis_not_configured_detail="not configured",
        sleep=AsyncMock(),
    )

    await process_analysis_queue_item(deps, item, finish_item)

    assert captured["user_guidance"] == "Check GHSA metadata gaps"
    assert completed["status"] == "completed"


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
