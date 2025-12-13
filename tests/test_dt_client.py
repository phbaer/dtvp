import pytest
import respx
from dt_client import DTClient

@pytest.fixture
def dt_client():
    return DTClient("http://dt.example.com", "api-key")

@pytest.mark.asyncio
async def test_get_projects(dt_client, respx_mock):
    respx_mock.get("http://dt.example.com/api/v1/project").respond(json=[
        {"name": "Proj1", "uuid": "u1"},
        {"name": "Proj2", "uuid": "u2"}
    ])
    
    projects = await dt_client.get_projects(name="Proj")
    assert len(projects) == 2
    assert projects[0]["name"] == "Proj1"

@pytest.mark.asyncio
async def test_get_vulnerabilities(dt_client, respx_mock):
    respx_mock.get("http://dt.example.com/api/v1/finding/project/u1").respond(json=[
        {"vulnerability": {"vulnId": "CVE-1"}}
    ])
    
    vulns = await dt_client.get_vulnerabilities("u1")
    assert len(vulns) == 1
    assert vulns[0]["vulnerability"]["vulnId"] == "CVE-1"

@pytest.mark.asyncio
async def test_update_analysis(dt_client, respx_mock):
    respx_mock.put("http://dt.example.com/api/v1/analysis").respond(json={"status": "updated"})
    
    res = await dt_client.update_analysis(
        project_uuid="p1",
        component_uuid="c1",
        vulnerability_uuid="v1",
        state="NOT_AFFECTED",
        details="Clean",
        comment="False positive",
        suppressed=True
    )
    assert res["status"] == "updated"

@pytest.mark.asyncio
async def test_get_analysis_404(dt_client, respx_mock):
    respx_mock.get("http://dt.example.com/api/v1/analysis").respond(status_code=404)
    
    res = await dt_client.get_analysis("p1", "c1", "v1")
    assert res is None

@pytest.mark.asyncio
async def test_get_vulnerabilities_with_enrichment(dt_client, respx_mock):
    # Mock findings response
    respx_mock.get("http://dt.example.com/api/v1/finding/project/u1").respond(json=[
        {
            "vulnerability": {"vulnId": "CVE-1", "uuid": "v1"},
            "component": {"uuid": "c1"}
        }
    ])
    
    # Mock analysis response
    respx_mock.get("http://dt.example.com/api/v1/analysis").respond(json={
        "state": "NOT_AFFECTED",
        "analysisDetails": "Test details"
    })
    
    vulns = await dt_client.get_vulnerabilities("u1")
    assert len(vulns) == 1
    assert vulns[0]["analysis"]["state"] == "NOT_AFFECTED"

@pytest.mark.asyncio
async def test_get_vulnerabilities_enrichment_failure(dt_client, respx_mock):
    # Mock findings response
    respx_mock.get("http://dt.example.com/api/v1/finding/project/u1").respond(json=[
        {
            "vulnerability": {"vulnId": "CVE-1", "uuid": "v1"},
            "component": {"uuid": "c1"}
        }
    ])
    
    # Mock analysis failure
    respx_mock.get("http://dt.example.com/api/v1/analysis").respond(status_code=500)
    
    # Should not raise, just continue without enrichment
    vulns = await dt_client.get_vulnerabilities("u1")
    assert len(vulns) == 1
    # Analysis should not be added
    assert "analysis" not in vulns[0] or vulns[0].get("analysis") is None

@pytest.mark.asyncio
async def test_get_project_vulnerabilities(dt_client, respx_mock):
    respx_mock.get("http://dt.example.com/api/v1/vulnerability/project/u1").respond(json=[
        {"vulnId": "CVE-1", "cvssV3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
    ])
    
    vulns = await dt_client.get_project_vulnerabilities("u1")
    assert len(vulns) == 1
    assert vulns[0]["cvssV3Vector"] is not None
