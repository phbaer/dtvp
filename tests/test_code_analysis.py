import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import dtvp.agentizer_integration as agentizer
import dtvp.code_analysis_integration as code_analysis
from dtvp import main
from dtvp.main import get_current_user


class DummyResponse:
    def __init__(self, data):
        self._data = data

    def raise_for_status(self):
        return None

    def json(self):
        return self._data


@pytest.fixture(autouse=True)
def override_auth():
    main.app.dependency_overrides[get_current_user] = lambda: "testuser"
    yield
    main.app.dependency_overrides.pop(get_current_user, None)


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
