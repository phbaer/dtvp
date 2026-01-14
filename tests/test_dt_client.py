import pytest
from dt_client import DTClient, DTSettings, get_client
from unittest.mock import patch
import respx
import httpx


@pytest.fixture
def dt_client():
    return DTClient("http://dt.example.com", "api-key")


@pytest.mark.asyncio
async def test_get_projects(dt_client, respx_mock):
    respx_mock.get("http://dt.example.com/api/v1/project").respond(
        json=[{"name": "Proj1", "uuid": "u1"}, {"name": "Proj2", "uuid": "u2"}]
    )

    projects = await dt_client.get_projects(name="Proj")
    assert len(projects) == 2
    assert projects[0]["name"] == "Proj1"


@pytest.mark.asyncio
async def test_get_projects_paginated(dt_client, respx_mock):
    # Page 1
    respx_mock.get("http://dt.example.com/api/v1/project").mock(
        side_effect=[
            httpx.Response(200, json=[{"name": "P1", "uuid": "u1"}] * 100),
            httpx.Response(200, json=[{"name": "P2", "uuid": "u2"}] * 50),
        ]
    )

    projects = await dt_client.get_projects(name="P")
    assert len(projects) == 150
    assert projects[0]["name"] == "P1"
    assert projects[149]["name"] == "P2"


@pytest.mark.asyncio
async def test_get_projects_empty(dt_client, respx_mock):
    respx_mock.get("http://dt.example.com/api/v1/project").respond(json=[])
    projects = await dt_client.get_projects(name="NonExistent")
    assert projects == []


@pytest.mark.asyncio
async def test_get_projects_boundary(dt_client, respx_mock):
    # Exactly one page (100 items), then empty
    respx_mock.get("http://dt.example.com/api/v1/project").mock(
        side_effect=[
            httpx.Response(200, json=[{"name": "P1", "uuid": "u1"}] * 100),
            httpx.Response(200, json=[]),
        ]
    )

    projects = await dt_client.get_projects(name="P")
    assert len(projects) == 100


@pytest.mark.asyncio
async def test_get_vulnerabilities(dt_client, respx_mock):
    respx_mock.get("http://dt.example.com/api/v1/finding/project/u1").respond(
        json=[{"vulnerability": {"vulnId": "CVE-1"}}]
    )

    vulns = await dt_client.get_vulnerabilities("u1")
    assert len(vulns) == 1
    assert vulns[0]["vulnerability"]["vulnId"] == "CVE-1"


@pytest.mark.asyncio
async def test_update_analysis(dt_client, respx_mock):
    respx_mock.put("http://dt.example.com/api/v1/analysis").respond(
        json={"status": "updated"}
    )

    res = await dt_client.update_analysis(
        project_uuid="p1",
        component_uuid="c1",
        vulnerability_uuid="v1",
        state="NOT_AFFECTED",
        details="Clean",
        comment="False positive",
        suppressed=True,
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
    respx_mock.get("http://dt.example.com/api/v1/finding/project/u1").respond(
        json=[
            {
                "vulnerability": {"vulnId": "CVE-1", "uuid": "v1"},
                "component": {"uuid": "c1"},
            }
        ]
    )

    # Mock analysis response
    respx_mock.get("http://dt.example.com/api/v1/analysis").respond(
        json={"state": "NOT_AFFECTED", "analysisDetails": "Test details"}
    )

    vulns = await dt_client.get_vulnerabilities("u1")
    assert len(vulns) == 1
    assert vulns[0]["analysis"]["state"] == "NOT_AFFECTED"


@pytest.mark.asyncio
async def test_get_vulnerabilities_enrichment_failure(dt_client, respx_mock):
    # Mock findings response
    respx_mock.get("http://dt.example.com/api/v1/finding/project/u1").respond(
        json=[
            {
                "vulnerability": {"vulnId": "CVE-1", "uuid": "v1"},
                "component": {"uuid": "c1"},
            }
        ]
    )

    # Mock analysis failure
    respx_mock.get("http://dt.example.com/api/v1/analysis").respond(status_code=500)

    # Should not raise, just continue without enrichment
    vulns = await dt_client.get_vulnerabilities("u1")
    assert len(vulns) == 1
    # Analysis should not be added
    assert "analysis" not in vulns[0] or vulns[0].get("analysis") is None


@pytest.mark.asyncio
async def test_get_project_vulnerabilities(dt_client, respx_mock):
    respx_mock.get("http://dt.example.com/api/v1/vulnerability/project/u1").respond(
        json=[
            {
                "vulnId": "CVE-1",
                "cvssV3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            }
        ]
    )

    vulns = await dt_client.get_project_vulnerabilities("u1")
    assert len(vulns) == 1
    assert vulns[0]["cvssV3Vector"] is not None


@pytest.mark.asyncio
async def test_get_project_versions():
    async with DTClient("http://url", "key") as client:
        res = await client.get_project_versions("uuid")
        assert res is None


def test_settings_properties():
    # Test fallbacks
    s = DTSettings(
        DTVP_DT_API_URL="",
        DEPENDENCY_TRACK_URL="http://fallback",
        DTVP_DT_API_KEY="",
        DEPENDENCY_TRACK_API_KEY="key",
    )

    assert s.api_url == "http://fallback"
    assert s.api_key == "key"

    s2 = DTSettings(
        DTVP_DT_API_URL="",
        DEPENDENCY_TRACK_URL=None,
        DTVP_DT_API_KEY="",
        DEPENDENCY_TRACK_API_KEY=None,
    )
    assert s2.api_url == "http://localhost:8081"
    assert s2.api_key == "change_me"


@pytest.mark.asyncio
async def test_get_client():
    with patch("dt_client.DTSettings") as mock_settings_cls:
        mock_instance = mock_settings_cls.return_value
        # If accessing the property returns a mock, that's fine, we just set the string conversion or use it as is?
        # But DTClient constructor expects string for rstrip.
        # So we must make sure api_url returns a string.
        mock_instance.api_url = "http://mock"
        mock_instance.api_key = "mock_key"

        async for c in get_client():
            assert c.base_url == "http://mock"
            assert c.headers["X-Api-Key"] == "mock_key"
            break


@respx.mock
@pytest.mark.asyncio
async def test_get_bom_error():
    settings = DTSettings(
        api_url="http://dependency-track",
        api_key="test_key",
    )
    # DTSettings determines URL.
    # If using DTSettings constructor, we set api_url explicitly.
    # However, DTClient logic might modify it or environment variables might interfere?
    # Wait, the failure says <Request('GET', 'http://localhost:8081/api/v1/bom/cyclonedx/project/uuid-error')>
    # This means api_url in settings was ignored or defaulted?
    # Ah, in test_settings_properties we saw fallbacks.
    # With `DTSettings(api_url="...")` passed to DTClient constructor, it checks arguments.
    # `def __init__(self, base_url: str, ...)`
    # The fixture failure implies base_url was 'http://localhost:8081'.
    # In my test:
    # settings = DTSettings(api_url=..., api_key=...)
    # But DTSettings is a Pydantic model. fields are DTVP_DT_API_URL etc.
    # 'api_url' is a computed property! I cannot pass it to constructor unless it's an alias?
    # No, I should pass DTVP_DT_API_URL="http://dependency-track"

    settings = DTSettings(
        DTVP_DT_API_URL="http://dependency-track",
        DTVP_DT_API_KEY="test_key",
    )

    # We also mocked respx specific URL.
    respx.get("http://dependency-track/api/v1/bom/cyclonedx/project/uuid-error").mock(
        return_value=httpx.Response(404)
    )

    async with DTClient(settings.api_url, settings.api_key) as client:
        with pytest.raises(httpx.HTTPStatusError):
            await client.get_bom("uuid-error")


@pytest.mark.asyncio
async def test_get_bom_success(respx_mock):
    dt_client = DTClient("http://dt.example.com", "api-key")
    respx_mock.get("http://dt.example.com/api/v1/bom/cyclonedx/project/u1").respond(
        json={"bomFormat": "CycloneDX"}
    )

    bom = await dt_client.get_bom("u1")
    assert bom["bomFormat"] == "CycloneDX"
