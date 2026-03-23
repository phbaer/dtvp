import pytest
import asyncio
import os
from unittest.mock import AsyncMock, patch
from httpx import AsyncClient
from main import app, get_current_user


@pytest.fixture(autouse=True)
def override_auth():
    app.dependency_overrides[get_current_user] = lambda: "testuser"
    yield
    # No need to clear here as conftest clears all overrides


def test_search_projects(client, mock_dt_client):
    mock_dt_client.get_projects.return_value = [
        {"name": "TestProj", "uuid": "uuid1", "version": "1.0"},
        {"name": "OtherProj", "uuid": "uuid2", "version": "1.0"},
    ]

    response = client.get("/api/projects?name=Test")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2
    assert data[0]["name"] == "TestProj"


def test_search_projects_no_name(client, mock_dt_client):
    mock_dt_client.get_projects.return_value = [
        {"name": "TestProj", "uuid": "uuid1", "version": "1.0"}
    ]

    response = client.get("/api/projects")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1


@pytest.mark.asyncio
async def test_get_grouped_vulns_task_flow(client, mock_dt_client):
    # Configure mock for context manager usage
    mock_dt_client.__aenter__.return_value = mock_dt_client
    mock_dt_client.__aexit__.return_value = None

    # Setup mocks
    mock_dt_client.get_projects.return_value = [
        {"name": "TestApp", "uuid": "uuid1", "version": "1.0"},
    ]

    # Mock get_vulnerabilities
    mock_dt_client.get_vulnerabilities.return_value = [
        {
            "vulnerability": {"vulnId": "CVE-1", "severity": "HIGH"},
            "component": {"name": "c1"},
            "analysis": {"state": "NOT_SET"},
        }
    ]
    # Mock project_vulnerabilities
    mock_dt_client.get_project_vulnerabilities.return_value = []
    # Mock get_bom
    mock_dt_client.get_bom.return_value = {}

    # Patch DTClient in main to return our mock when instantiated
    with patch("main.DTClient", return_value=mock_dt_client):
        # 1. Start Task
        response = client.post("/api/tasks/group-vulns?name=TestApp")
        assert response.status_code == 200
        task_id = response.json()["task_id"]

        # 2. Poll Status
        await asyncio.sleep(0.1)

        response = client.get(f"/api/tasks/{task_id}")
        assert response.status_code == 200
        status = response.json()

        # Poll loop
        for _ in range(10):
            if status["status"] == "completed":
                break
            await asyncio.sleep(0.1)
            response = client.get(f"/api/tasks/{task_id}")
            status = response.json()
            if status["status"] == "failed":
                pytest.fail(f"Task failed: {status['message']}")

    assert status["status"] == "completed"
    data = status["result"]

    assert len(data) == 1
    assert data[0]["id"] == "CVE-1"
    assert len(data[0]["affected_versions"]) == 1


@pytest.mark.asyncio
async def test_get_grouped_vulns_no_projects(client, mock_dt_client):
    # Configure mock
    mock_dt_client.__aenter__.return_value = mock_dt_client
    mock_dt_client.__aexit__.return_value = None
    mock_dt_client.get_projects.return_value = []

    with patch("main.DTClient", return_value=mock_dt_client):
        # Start task
        response = client.post("/api/tasks/group-vulns?name=NonExistent")
        assert response.status_code == 200
        task_id = response.json()["task_id"]

        # Poll until complete
        for _ in range(10):
            await asyncio.sleep(0.1)
            response = client.get(f"/api/tasks/{task_id}")
            status = response.json()
            if status["status"] == "completed":
                break

        assert status["status"] == "completed"
        assert status["result"] == []


@pytest.mark.asyncio
async def test_get_grouped_vulns_task_failure(client, mock_dt_client):
    # Configure mock
    mock_dt_client.__aenter__.return_value = mock_dt_client
    mock_dt_client.__aexit__.return_value = None
    mock_dt_client.get_projects.side_effect = Exception("DT API Down")

    with patch("main.DTClient", return_value=mock_dt_client):
        response = client.post("/api/tasks/group-vulns?name=ErrorApp")
        task_id = response.json()["task_id"]

        # Poll
        for _ in range(10):
            await asyncio.sleep(0.1)
            response = client.get(f"/api/tasks/{task_id}")
            status = response.json()
            if status["status"] == "failed":
                break

        assert status["status"] == "failed"
        assert "DT API Down" in status["message"]


def test_get_task_status_not_found(client):
    response = client.get("/api/tasks/unknown-id")
    assert response.status_code == 200
    assert response.json()["status"] == "not_found"


@pytest.mark.asyncio
async def test_statistics_major_version_split(client, mock_dt_client):
    mock_dt_client.__aenter__.return_value = mock_dt_client
    mock_dt_client.__aexit__.return_value = None

    mock_dt_client.get_projects.return_value = [
        {"name": "TestApp", "uuid": "uuid1", "version": "1.0.0"},
        {"name": "TestApp", "uuid": "uuid2", "version": "2.0.0"},
    ]

    mock_dt_client.get_vulnerabilities.side_effect = [
        [
            {
                "vulnerability": {"vulnId": "CVE-1", "severity": "HIGH"},
                "component": {"name": "lib", "version": "1.0", "uuid": "comp1"},
                "analysis": {"state": "NOT_SET"},
            }
        ],
        [
            {
                "vulnerability": {"vulnId": "CVE-2", "severity": "CRITICAL"},
                "component": {"name": "lib", "version": "1.1", "uuid": "comp2"},
                "analysis": {"state": "NOT_SET"},
            }
        ],
    ]

    mock_dt_client.get_project_vulnerabilities.return_value = []
    mock_dt_client.get_bom.return_value = {}

    with patch("main.DTClient", return_value=mock_dt_client):
        response = client.get("/api/statistics?name=TestApp")
        assert response.status_code == 200
        data = response.json()

        assert data["version_counts"]["1.0.0"] == 1
        assert data["version_counts"]["2.0.0"] == 1
        assert data["major_version_counts"]["1"] == 1
        assert data["major_version_counts"]["2"] == 1
        assert data["version_severity_counts"]["1.0.0"]["HIGH"] == 1
        assert data["version_severity_counts"]["2.0.0"]["CRITICAL"] == 1
        assert data["major_version_severity_counts"]["1"]["HIGH"] == 1
        assert data["major_version_severity_counts"]["2"]["CRITICAL"] == 1
        assert data["severity_counts"]["HIGH"] == 1
        assert data["severity_counts"]["CRITICAL"] == 1
        assert data["unique_severity_counts"]["HIGH"] == 1
        assert data["unique_severity_counts"]["CRITICAL"] == 1
        assert data["finding_state_counts"]["NOT_SET"] == 2
async def test_grouped_vulnerabilities_with_vector_merge(client, mock_dt_client):
    # Configure mock
    mock_dt_client.__aenter__.return_value = mock_dt_client
    mock_dt_client.__aexit__.return_value = None

    # Mock projects
    mock_dt_client.get_projects.return_value = [
        {"name": "TestProj", "uuid": "uuid1", "version": "1.0"}
    ]

    # Mock findings without vector
    mock_dt_client.get_vulnerabilities.return_value = [
        {
            "vulnerability": {
                "vulnId": "CVE-2023-001",
                "uuid": "vuuid1",
                "severity": "HIGH",
            },
            "component": {"name": "lib", "version": "1.0", "uuid": "comp1"},
            "analysis": {"state": "NOT_SET"},
        }
    ]

    # Mock full vulnerabilities with vector
    mock_dt_client.get_project_vulnerabilities.return_value = [
        {
            "vulnId": "CVE-2023-001",
            "cvssV3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvssV3BaseScore": 9.8,
        }
    ]
    # Mock get_bom
    mock_dt_client.get_bom.return_value = {}

    with patch("main.DTClient", return_value=mock_dt_client):
        # Start Task
        response = client.post("/api/tasks/group-vulns?name=TestProj")
        assert response.status_code == 200
        task_id = response.json()["task_id"]

        # Poll until done
        for _ in range(10):
            await asyncio.sleep(0.1)
            response = client.get(f"/api/tasks/{task_id}")
            if response.json()["status"] == "completed":
                break

    status = response.json()
    assert status["status"] == "completed"
    data = status["result"]

    assert len(data) == 1
    # Verify vector was merged
    assert data[0]["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert data[0]["cvss_score"] == 9.8


def test_get_sbom_endpoints(client, tmp_path):
    sbom_dir = tmp_path / "sbom"
    sbom_dir.mkdir(parents=True, exist_ok=True)

    # Create backend and frontend BOM files as well as default
    backend_path = sbom_dir / "dtvp-backend-cyclonedx.json"
    frontend_path = sbom_dir / "dtvp-frontend-cyclonedx.json"
    default_path = sbom_dir / "dtvp-cyclonedx.json"

    backend_path.write_text('{"bomFormat": "CycloneDX", "type": "backend"}')
    frontend_path.write_text('{"bomFormat": "CycloneDX", "type": "frontend"}')
    default_path.write_text('{"bomFormat": "CycloneDX", "type": "default"}')

    # Monkey-patch working directory for the app
    original_cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        r = client.get("/api/sbom")
        assert r.status_code == 200
        assert r.json()["type"] == "backend"

        r = client.get("/api/sbom/backend")
        assert r.status_code == 200
        assert r.json()["type"] == "backend"

        r = client.get("/api/sbom/frontend")
        assert r.status_code == 200
        assert r.json()["type"] == "frontend"
    finally:
        os.chdir(original_cwd)


def test_assessment_update(client, mock_dt_client):
    payload = {
        "instances": [
            {
                "project_uuid": "puuid",
                "component_uuid": "cuuid",
                "vulnerability_uuid": "vuuid",
                "finding_uuid": "fuuid",
            }
        ],
        "state": "NOT_AFFECTED",
        "details": "Verified as false positive",
        "comment": "False positive",
        "suppressed": True,
    }

    with patch("main.get_user_role", return_value="REVIEWER"):
        response = client.post("/api/assessment", json=payload)
        assert response.status_code == 200
        results = response.json()
        assert len(results) == 1
        assert results[0]["status"] == "success"

    # Verify client call
    mock_dt_client.update_analysis.assert_called_once()
    call_kwargs = mock_dt_client.update_analysis.call_args.kwargs
    assert call_kwargs["project_uuid"] == "puuid"
    assert call_kwargs["state"] == "NOT_AFFECTED"
    # Details now includes the appended user tag
    assert "Verified as false positive" in call_kwargs["details"]
    assert "[Reviewed By: testuser]" in call_kwargs["details"]
    assert call_kwargs["suppressed"] is True


def test_assessment_update_failure(client, mock_dt_client):
    mock_dt_client.update_analysis.side_effect = Exception("Analysis update failed")

    payload = {
        "instances": [
            {
                "project_uuid": "p1",
                "component_uuid": "c1",
                "vulnerability_uuid": "v1",
                "finding_uuid": "f1",
            }
        ],
        "state": "NOT_AFFECTED",
        "details": "Fail",
    }

    response = client.post("/api/assessment", json=payload)
    assert response.status_code == 200
    results = response.json()
    assert len(results) == 1
    assert results[0]["status"] == "error"
    assert "Analysis update failed" in results[0]["error"]


def test_spa_routing(client):
    # Check if SPA route matches expected catch-all pattern
    # The route path depends on context_path, so finding it by name or analyzing paths is needed.
    # main.py defines it as f"{context_path}/{{path:path}}"

    spa_route_exists = False
    for route in app.routes:
        if hasattr(route, "path") and "{path:path}" in route.path:
            spa_route_exists = True
            break

    if not spa_route_exists:
        pytest.skip("SPA routing not enabled (frontend/dist missing)")

    # Ensure dummy asset exists for test
    import os

    os.makedirs("frontend/dist/assets", exist_ok=True)
    with open("frontend/dist/assets/test.css", "w") as f:
        f.write("body {}")

    # 1. Catch-all route should return index.html for unknown paths
    response = client.get("/projects")  # Client-side route
    assert response.status_code == 200

    # 2. Static assets
    response = client.get("/assets/test.css")
    assert response.status_code == 200

    # 3. Path traversal attempt should return index.html
    response = client.get("/../etc/passwd")
    assert response.status_code == 200
