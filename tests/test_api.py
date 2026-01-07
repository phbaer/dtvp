import pytest
from unittest.mock import AsyncMock
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


@pytest.mark.asyncio
async def test_get_grouped_vulns(client, mock_dt_client):
    # Setup mocks
    mock_dt_client.get_projects.return_value = [
        {"name": "TestApp", "uuid": "uuid1", "version": "1.0"},
        {"name": "TestApp", "uuid": "uuid2", "version": "2.0"},
        # This one shouldn't be touched if we filter by name correctly in endpoint?
        # The endpoint logic filters: projects = await client.get_projects(name)
        # then versions = [p for p in projects if p.get("name") == name]
        {"name": "OtherApp", "uuid": "uuid3", "version": "1.0"},
    ]

    # Mock get_vulnerabilities for each version
    # Since it calls client.get_vulnerabilities(uuid), we can just return a generic list or side_effect
    async def get_vulns_side_effect(uuid):
        if uuid == "uuid1":
            return [
                {
                    "vulnerability": {"vulnId": "CVE-1", "severity": "HIGH"},
                    "component": {"name": "c1"},
                    "analysis": {"state": "NOT_SET"},
                }
            ]
        elif uuid == "uuid2":
            return []
        return []

    mock_dt_client.get_vulnerabilities.side_effect = get_vulns_side_effect

    response = client.get("/api/projects/TestApp/grouped-vulnerabilities")
    assert response.status_code == 200
    data = response.json()


    assert len(data) == 1
    assert data[0]["id"] == "CVE-1"
    assert len(data[0]["affected_versions"]) == 1
    assert data[0]["affected_versions"][0]["project_version"] == "1.0"
    assert len(data[0]["affected_versions"][0]["components"]) == 1


def test_get_grouped_vulns_no_projects(client, mock_dt_client):
    mock_dt_client.get_projects.return_value = []
    response = client.get("/api/projects/NonExistent/grouped-vulnerabilities")
    assert response.status_code == 200
    assert response.json() == []


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
    assert call_kwargs["details"] == "Verified as false positive"
    assert call_kwargs["suppressed"] is True


def test_assessment_update_failure(client, mock_dt_client):
    mock_dt_client.update_analysis.side_effect = Exception("Analysis update failed")
    
    payload = {
        "instances": [
             {"project_uuid": "p1", "component_uuid": "c1", "vulnerability_uuid": "v1", "finding_uuid": "f1"}
        ],
        "state": "NOT_AFFECTED",
        "details": "Fail"
    }
    
    response = client.post("/api/assessment", json=payload)
    assert response.status_code == 200
    results = response.json()
    assert len(results) == 1
    assert results[0]["status"] == "error"
    assert "Analysis update failed" in results[0]["error"]


@pytest.mark.asyncio
async def test_grouped_vulnerabilities_with_vector_merge(client, mock_dt_client):
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
            "cvssV3BaseScore": 9.8
        }
    ]
    
    response = client.get("/api/projects/TestProj/grouped-vulnerabilities")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    # Verify vector was merged
    assert data[0]["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert data[0]["cvss_score"] == 9.8


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
    response = client.get("/projects") # Client-side route
    assert response.status_code == 200
    # Ideally check content is index.html (empty file in our mock)
    # But FileResponse might fail if file empty? 
    # Valid index.html content
    
    # 2. Static assets
    response = client.get("/assets/test.css")
    assert response.status_code == 200
    
    # 3. Path traversal attempt should return index.html
    response = client.get("/../etc/passwd")
    assert response.status_code == 200
    # Should be index.html, not passwd
