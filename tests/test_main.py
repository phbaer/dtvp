import asyncio
import importlib
import os
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from dtvp import main


@pytest.fixture(autouse=True)
def override_auth():
    main.app.dependency_overrides[main.get_current_user] = lambda: "testuser"
    yield


def test_openapi_endpoint(client):
    response = client.get("/api/openapi.json")
    assert response.status_code == 200
    assert "openapi" in response.json()


def test_get_version(client):
    response = client.get("/api/version")
    assert response.status_code == 200
    assert "version" in response.json()
    assert "build" in response.json()


def test_startup_status_endpoint_reports_runtime_state(client):
    original_state = dict(main.app_runtime_state)
    main.app_runtime_state.update(
        {
            "status": "starting",
            "message": "Preparing runtime.",
            "error": None,
        }
    )
    try:
        response = client.get("/api/startup")
    finally:
        main.app_runtime_state.clear()
        main.app_runtime_state.update(original_state)

    assert response.status_code == 200
    assert response.json() == {
        "status": "starting",
        "ready": False,
        "message": "Preparing runtime.",
    }


def test_startup_gate_serves_page_for_browser_routes(client):
    original_state = dict(main.app_runtime_state)
    main.app_runtime_state.update(
        {
            "status": "starting",
            "message": "Preparing runtime.",
            "error": None,
        }
    )
    try:
        response = client.get("/")
    finally:
        main.app_runtime_state.clear()
        main.app_runtime_state.update(original_state)

    assert response.status_code == 200
    assert "DTVP is starting" in response.text
    assert "Preparing runtime." in response.text
    assert '"/api/startup"' in response.text


def test_startup_gate_returns_503_for_api_routes(client):
    original_state = dict(main.app_runtime_state)
    main.app_runtime_state.update(
        {
            "status": "starting",
            "message": "Preparing runtime.",
            "error": None,
        }
    )
    try:
        response = client.get("/api/version")
    finally:
        main.app_runtime_state.clear()
        main.app_runtime_state.update(original_state)

    assert response.status_code == 503
    assert response.headers["retry-after"] == "2"
    assert response.json()["ready"] is False


def test_lifespan_serves_startup_page_while_runtime_initializes():
    async def slow_initialize():
        await asyncio.sleep(1)

    with patch.object(main.cache_manager, "initialize", slow_initialize):
        with TestClient(main.app) as startup_client:
            response = startup_client.get("/")

    assert response.status_code == 200
    assert "DTVP is starting" in response.text


def test_main_context_path_reload():
    # Test line 28: context_path = "/" + context_path
    from unittest.mock import patch

    # We need to simulate DTVP_CONTEXT_PATH="myctx" (no slash)
    # Since main imports auth_settings, we need to patch that or env before reload

    from dtvp import auth
    from dtvp import main

    try:
        with patch.dict(os.environ, {"DTVP_CONTEXT_PATH": "myctx"}):
            # We must also reload auth to pick up new env vars into AuthSettings if it's instantiated at module level
            importlib.reload(auth)
            importlib.reload(main)

            assert main.context_path == "/myctx"

            client = TestClient(main.app)
            resp = client.get("/myctx/api/version")
            assert resp.status_code == 200

            # Also check redirect_to_context_path (lines 161-163)
            # app.get(context_path) -> redirect to context_path/
            resp = client.get("/myctx", follow_redirects=False)
            assert resp.status_code == 307
            assert resp.headers["location"] == "/myctx/"
    finally:
        # Restore main to default even if an assertion fails, otherwise later tests
        # keep using a context-prefixed app and fail with cascading 404s.
        importlib.reload(auth)
        importlib.reload(main)


def test_process_grouped_vulns_task_bom_failure():
    from unittest.mock import AsyncMock

    from dtvp import main
    from dtvp.grouped_vuln_services import process_grouped_vulns_task

    client = AsyncMock()
    client.get_projects.return_value = [
        {"name": "Test", "version": "1.0", "uuid": "u1"}
    ]
    client.get_vulnerabilities.return_value = []
    client.get_project_vulnerabilities.return_value = []
    # Force get_bom to fail
    client.get_bom.side_effect = Exception("Forbidden")

    task_id = "test-task"
    main.tasks[task_id] = {"status": "pending"}

    import asyncio

    asyncio.run(
        process_grouped_vulns_task(
            main.grouped_vuln_service_deps,
            task_id,
            "Test",
            None,
            client,
        )
    )

    assert main.tasks[task_id]["status"] == "completed"
    assert main.tasks[task_id]["result"] == []


def test_process_grouped_vulns_task_all_projects():
    from unittest.mock import AsyncMock

    from dtvp import main
    from dtvp.grouped_vuln_services import process_grouped_vulns_task

    client = AsyncMock()
    # Mock multiple different projects
    client.get_projects.return_value = [
        {"name": "ProjA", "version": "1.0", "uuid": "u1"},
        {"name": "ProjB", "version": "2.0", "uuid": "u2"},
    ]
    client.get_vulnerabilities.return_value = []
    client.get_project_vulnerabilities.return_value = []
    client.get_bom.return_value = {"components": []}

    task_id = "test-all-task"
    main.tasks[task_id] = {"status": "pending"}

    import asyncio

    # Call with empty name (All projects request)
    asyncio.run(
        process_grouped_vulns_task(
            main.grouped_vuln_service_deps,
            task_id,
            "",
            None,
            client,
        )
    )

    assert main.tasks[task_id]["status"] == "completed"
    # Verify that BOTH projects were processed (they would be in combined_data)
    # Since vulnerabilities were empty, result is empty list, but we can verify the mock calls if we wanted.
    # Actually, let's verify get_vulnerabilities was called for BOTH uuids.
    assert client.get_vulnerabilities.call_count == 2
    calls = [c.args[0] for c in client.get_vulnerabilities.call_args_list]
    assert "u1" in calls
    assert "u2" in calls


def test_summary_task_seeds_from_persistent_summary_index():
    import asyncio

    from dtvp.grouped_vuln_services import (
        GroupedVulnServiceDeps,
        process_grouped_vulns_task,
    )

    task_id = "summary-cache-seed"
    tasks = {task_id: {"status": "pending", "log": []}}

    class FakeCacheManager:
        async def get_projects(self, client, name):
            return [{"name": "Test", "version": "1.0", "uuid": "u1"}]

        async def get_vulnerabilities(self, client, project_uuid, cve=None):
            assert tasks[task_id]["partial_result_available"] is True
            assert tasks[task_id]["partial_source"] == "summary_index"
            assert tasks[task_id]["result"][0]["id"] == "CVE-CACHED"
            return [
                {
                    "vulnerability": {
                        "vulnId": "CVE-LIVE",
                        "severity": "HIGH",
                    },
                    "component": {
                        "name": "library-a",
                        "uuid": "component-1",
                        "version": "1.0",
                    },
                    "analysis": {"state": "NOT_SET"},
                }
            ]

        async def get_project_vulnerabilities(self, client, project_uuid):
            return []

        async def get_bom(self, client, project_uuid):
            return {}

    class FakeSummaryIndex:
        def __init__(self):
            self.saved = []

        def load(self, cache_key):
            return {
                "result": [
                    {
                        "id": "CVE-CACHED",
                        "title": "Cached",
                        "tags": [],
                        "aliases": [],
                        "assignees": [],
                        "affected_versions": [],
                        "list_metadata": {
                            "lifecycle": "OPEN",
                            "is_open": True,
                            "is_pending": False,
                            "technical_state": "NOT_SET",
                        },
                    }
                ],
                "statistics_rollup": {"version_counts": {"1.0": 1}},
                "total_versions": 1,
            }

        def save(
            self,
            cache_key,
            *,
            scope,
            summaries,
            statistics_rollup,
            total_versions,
        ):
            self.saved.append(
                {
                    "cache_key": cache_key,
                    "scope": scope,
                    "summaries": summaries,
                    "statistics_rollup": statistics_rollup,
                    "total_versions": total_versions,
                }
            )

    summary_index = FakeSummaryIndex()

    def group_vulnerabilities(combined_data, **kwargs):
        return [
            {
                "id": "CVE-LIVE",
                "title": "Live",
                "severity": "HIGH",
                "cvss_score": 8.0,
                "tags": ["Team"],
                "aliases": [],
                "assignees": [],
                "affected_versions": [
                    {
                        "project_name": "Test",
                        "project_version": "1.0",
                        "project_uuid": "u1",
                        "components": [
                            {
                                "component_name": "library-a",
                                "component_version": "1.0",
                                "component_uuid": "component-1",
                                "project_uuid": "u1",
                                "analysis_state": "NOT_SET",
                                "is_direct_dependency": True,
                            }
                        ],
                    }
                ],
            }
        ]

    deps = GroupedVulnServiceDeps(
        cache_manager=FakeCacheManager(),
        logger=main.logger,
        tasks=tasks,
        bom_analysis_cache_cls=lambda bom, team_mapping: {},
        get_version_fetch_concurrency=lambda: 1,
        merge_vulnerability_details=lambda findings, full_vulns: {
            "HIGH": len(findings)
        },
        sort_projects_by_version=lambda versions: versions,
        load_team_mapping=lambda: {"*": "Team"},
        group_vulnerabilities=group_vulnerabilities,
        summary_index=summary_index,
        summary_index_cache_revision=lambda: "rev-1",
    )

    asyncio.run(
        process_grouped_vulns_task(
            deps,
            task_id,
            "Test",
            None,
            client=object(),
            response_mode="summary",
        )
    )

    assert tasks[task_id]["status"] == "completed"
    assert tasks[task_id]["result"][0]["id"] == "CVE-LIVE"
    assert tasks[task_id]["partial_result_available"] is False
    assert summary_index.saved[0]["summaries"][0]["id"] == "CVE-LIVE"
    assert summary_index.saved[0]["total_versions"] == 1


def test_spa_traversal_logic():
    from dtvp import main

    # Ensure we have the spa route
    # If frontend/dist exists, it should be there.
    if not os.path.exists("frontend/dist"):
        pytest.skip("frontend/dist not found")

    client = TestClient(main.app)

    # Create valid file
    with open("frontend/dist/valid.txt", "w") as f:
        f.write("content")

    # 1. Test existing file
    # We need to know current context path. Default is /
    # So /valid.txt
    resp = client.get("/valid.txt")
    assert resp.status_code == 200
    assert resp.content == b"content"

    # 2. Test traversal ".."
    # TestClient/Starlette might resolve /../ so use a path that keeps ..
    # The check in main.py is simply 'if ".." in path:'
    resp = client.get("/suspicious..check")
    assert resp.status_code == 200
    # Should serve modified index.html
    # We expect some replacements
    assert b"window.__env__ =" in resp.content


def test_serve_index_with_context():
    from unittest.mock import patch

    from dtvp import main

    if not os.path.exists("frontend/dist/index.html"):
        pytest.skip("frontend/dist/index.html not found")

    with patch("dtvp.main.context_path", "/myctx"):
        client = TestClient(main.app)
        resp = client.get("/myctx/some-page")
        assert resp.status_code == 200
        # Check if absolute paths were replaced
        assert b'src="/myctx/' in resp.content or b'href="/myctx/' in resp.content


def test_serve_index_not_found():
    from unittest.mock import patch

    from dtvp import main

    # Mock open to fail inside serve_index
    with patch("builtins.open", side_effect=FileNotFoundError("No index")):
        client = TestClient(main.app)
        # We need a path that triggers serve_spa -> serve_index
        # But wait, serve_spa is only defined if dist exists.
        # If it's already defined, we trigger it.
        resp = client.get("/any-path-to-trigger-spa")
        if resp.status_code != 404:  # If the route doesn't exist at all skip
            # It might return 200 if frontend/dist existed when app started
            assert b"Frontend not found" in resp.content
            assert resp.status_code == 404


def test_upload_mapping(client):
    from unittest.mock import mock_open, patch

    mapping_content = b'{"comp": "team"}'
    files = {"file": ("mapping.json", mapping_content, "application/json")}

    # We mock get_team_mapping_path to avoid overwriting real data/temp files
    with patch("dtvp.main.get_user_role", return_value="REVIEWER"):
        with patch(
            "dtvp.main.get_team_mapping_path", return_value="/tmp/test_mapping.json"
        ):
            with patch(
                "builtins.open", mock_open(read_data='{"test": "data"}')
            ) as mocked_file:
                response = client.post("/api/settings/mapping", files=files)

                assert response.status_code == 200
                assert response.json()["status"] == "success"

            # Verify file write
            mocked_file.assert_called_with(
                "/tmp/test_mapping.json", "r"
            )  # It opens for read at end too


def test_upload_mapping_failure(client):
    from unittest.mock import patch

    mapping_content = b"invalid"
    files = {"file": ("mapping.json", mapping_content, "application/json")}

    # Mock open to raise exception on write or processing
    with patch("dtvp.main.get_user_role", return_value="REVIEWER"):
        with patch(
            "dtvp.main.get_team_mapping_path", return_value="/tmp/test_mapping.json"
        ):
            with patch("builtins.open", side_effect=Exception("Disk full")):
                response = client.post("/api/settings/mapping", files=files)

                assert response.status_code == 200
            data = response.json()
            assert data["status"] == "error"
            assert "Disk full" in data["message"]


def test_get_team_mapping(client):
    from unittest.mock import patch

    with patch("dtvp.main.get_user_role", return_value="REVIEWER"):
        with patch("dtvp.main.load_team_mapping", return_value={"test": "team"}):
            response = client.get("/api/settings/mapping")
            assert response.status_code == 200
            assert response.json() == {"test": "team"}


def test_get_team_mapping_forbidden_for_analyst(client):
    from unittest.mock import patch

    with patch("dtvp.main.get_user_role", return_value="ANALYST"):
        response = client.get("/api/settings/mapping")
        assert response.status_code == 403
        assert "Only reviewers" in response.json()["detail"]


def test_upload_mapping_forbidden_for_analyst(client):
    from unittest.mock import patch

    mapping_content = b'{"comp": "team"}'
    files = {"file": ("mapping.json", mapping_content, "application/json")}

    with patch("dtvp.main.get_user_role", return_value="ANALYST"):
        response = client.post("/api/settings/mapping", files=files)
        assert response.status_code == 403
        assert "Only reviewers" in response.json()["detail"]


def test_serve_index_no_frontend_url():
    from unittest.mock import patch

    from dtvp import main

    if not os.path.exists("frontend/dist/index.html"):
        pytest.skip("frontend/dist/index.html not found")

    # Patch FRONTEND_URL to trigger line 356
    with patch("dtvp.main.auth_settings.FRONTEND_URL", None):
        client = TestClient(main.app)
        resp = client.get("/any-path")
        assert resp.status_code == 200
        assert b"window.__env__ =" in resp.content
