import pytest
import os
import importlib
from fastapi.testclient import TestClient


def test_openapi_endpoint(client):
    response = client.get("/api/openapi.json")
    if response.status_code == 404:
        # Maybe context path is set?
        # Try finding the route
        pass
    assert response.status_code == 200
    assert "openapi" in response.json()


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
    # Should serve index.html
    with open("frontend/dist/index.html", "rb") as f:
        idx = f.read()
    assert resp.content == idx
