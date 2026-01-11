import pytest
import os
import importlib
from fastapi.testclient import TestClient
from main import app, get_current_user


@pytest.fixture(autouse=True)
def override_auth():
    app.dependency_overrides[get_current_user] = lambda: "testuser"
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


def test_main_context_path_reload():
    # Test line 28: context_path = "/" + context_path
    from unittest.mock import patch

    # We need to simulate DTVP_CONTEXT_PATH="myctx" (no slash)
    # Since main imports auth_settings, we need to patch that or env before reload

    with patch.dict(os.environ, {"DTVP_CONTEXT_PATH": "myctx"}):
        # We must also reload auth to pick up new env vars into AuthSettings if it's instantiated at module level
        import auth

        importlib.reload(auth)

        import main

        importlib.reload(main)

        # Check routes for /myctx prefix
        found = False
        for route in main.app.routes:
            if route.path.startswith("/myctx/api"):
                found = True
                break
        assert found

        # Also check redirect_to_context_path (lines 161-163)
        # app.get(context_path) -> redirect to context_path/
        client = TestClient(main.app)
        resp = client.get("/myctx", follow_redirects=False)
        assert resp.status_code == 307
        assert resp.headers["location"] == "/myctx/"

    # Restore main to default for safety
    importlib.reload(auth)
    importlib.reload(main)


def test_process_grouped_vulns_task_bom_failure():
    import main
    from unittest.mock import AsyncMock

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

    asyncio.run(main.process_grouped_vulns_task(task_id, "Test", client))

    assert main.tasks[task_id]["status"] == "completed"
    assert main.tasks[task_id]["result"] == []


def test_spa_traversal_logic():
    import main

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
    import main
    from unittest.mock import patch

    if not os.path.exists("frontend/dist/index.html"):
        pytest.skip("frontend/dist/index.html not found")

    with patch("main.context_path", "/myctx"):
        client = TestClient(main.app)
        resp = client.get("/myctx/some-page")
        assert resp.status_code == 200
        # Check if absolute paths were replaced
        assert b'src="/myctx/' in resp.content or b'href="/myctx/' in resp.content


def test_serve_index_not_found():
    import main
    from unittest.mock import patch

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
    from unittest.mock import patch, mock_open

    mapping_content = b'{"comp": "team"}'
    files = {"file": ("mapping.json", mapping_content, "application/json")}

    # We mock get_team_mapping_path to avoid overwriting real data/temp files
    with patch("main.get_team_mapping_path", return_value="/tmp/test_mapping.json"):
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
    with patch("main.get_team_mapping_path", return_value="/tmp/test_mapping.json"):
        with patch("builtins.open", side_effect=Exception("Disk full")):
            response = client.post("/api/settings/mapping", files=files)

            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "error"
            assert "Disk full" in data["message"]


def test_get_team_mapping(client):
    from unittest.mock import patch

    with patch("main.load_team_mapping", return_value={"test": "team"}):
        response = client.get("/api/settings/mapping")
        assert response.status_code == 200
        assert response.json() == {"test": "team"}

def test_serve_index_no_frontend_url():
    import main
    from unittest.mock import patch

    if not os.path.exists("frontend/dist/index.html"):
        pytest.skip("frontend/dist/index.html not found")

    # Patch FRONTEND_URL to trigger line 356
    with patch("main.auth_settings.FRONTEND_URL", None):
        client = TestClient(main.app)
        resp = client.get("/any-path")
        assert resp.status_code == 200
        assert b"window.__env__ =" in resp.content
