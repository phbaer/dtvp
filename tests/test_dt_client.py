import pytest
from dtvp.dt_client import DTClient, DTSettings, get_client
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
async def test_update_analysis_justification(dt_client, respx_mock):
    respx_mock.put("http://dt.example.com/api/v1/analysis").respond(
        json={"status": "updated"}
    )

    res = await dt_client.update_analysis(
        project_uuid="p1",
        component_uuid="c1",
        vulnerability_uuid="v1",
        state="NOT_AFFECTED",
        details="Clean",
        justification="CODE_NOT_PRESENT",
    )
    assert res["status"] == "updated"
    # Verify exact payload if possible, but respx_mock's put check is enough or we can add it
    request = respx_mock.calls.last.request
    import json

    payload = json.loads(request.content)
    assert payload["analysisJustification"] == "CODE_NOT_PRESENT"


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


@pytest.mark.asyncio
async def test_find_project_by_name_version_matches_exact_version(dt_client, respx_mock):
    respx_mock.get("http://dt.example.com/api/v1/project").respond(
        json=[
            {"name": "ArchiveApp", "version": "1.0.0", "uuid": "p1"},
            {"name": "ArchiveApp", "version": "2.0.0", "uuid": "p2"},
        ]
    )

    project = await dt_client.find_project_by_name_version("ArchiveApp", "2.0.0")

    assert project == {"name": "ArchiveApp", "version": "2.0.0", "uuid": "p2"}


@pytest.mark.asyncio
async def test_upload_bom_auto_creates_project_version(dt_client, respx_mock):
    respx_mock.post("http://dt.example.com/api/v1/bom").respond(
        json={"token": "upload-token"}
    )

    result = await dt_client.upload_bom(
        {"bomFormat": "CycloneDX", "components": []},
        project_name="ArchiveApp",
        project_version="1.0.0",
        auto_create=True,
    )

    assert result == {"token": "upload-token"}
    request = respx_mock.calls.last.request
    body = request.content.decode("utf-8")
    assert 'name="autoCreate"' in body
    assert "true" in body
    assert 'name="projectName"' in body
    assert "ArchiveApp" in body
    assert 'name="projectVersion"' in body
    assert "1.0.0" in body


def test_settings_properties():
    generic = DTSettings(
        _env_file=None,
        DTVP_VULNERABILITY_BACKEND_API_URL="https://backend.example",
        DTVP_VULNERABILITY_BACKEND_API_KEY="generic-key",
        DTVP_DT_API_URL="https://legacy.example",
        DTVP_DT_API_KEY="legacy-key",
    )
    assert generic.api_url == "https://backend.example"
    assert generic.api_key == "generic-key"

    # Legacy settings remain readable for existing adapter deployments.
    s = DTSettings(
        _env_file=None,
        DTVP_VULNERABILITY_BACKEND_API_URL="",
        DTVP_VULNERABILITY_BACKEND_API_KEY="",
        DTVP_DT_API_URL="",
        DEPENDENCY_TRACK_URL="http://fallback",
        DTVP_DT_API_KEY="change_me",
        DEPENDENCY_TRACK_API_KEY="key",
    )

    assert s.api_url == "http://fallback"
    assert s.api_key == "key"

    s2 = DTSettings(
        _env_file=None,
        DTVP_VULNERABILITY_BACKEND_API_URL="",
        DTVP_VULNERABILITY_BACKEND_API_KEY="",
        DTVP_DT_API_URL="",
        DEPENDENCY_TRACK_URL=None,
        DTVP_DT_API_KEY="change_me",
        DEPENDENCY_TRACK_API_KEY=None,
    )
    assert s2.api_url == ""
    assert s2.api_key == ""


@pytest.mark.asyncio
async def test_get_client():
    with patch("dtvp.dt_client.DTSettings") as mock_settings_cls:
        mock_instance = mock_settings_cls.return_value
        mock_instance.api_url = "http://mock"
        mock_instance.api_key = "mock_key"

        async for c in get_client():
            assert c.base_url == "http://mock"
            assert c.headers["X-Api-Key"] == "mock_key"
            break


@pytest.mark.asyncio
async def test_get_client_does_not_forward_request_credentials():
    with patch("dtvp.dt_client.DTSettings") as mock_settings_cls:
        mock_instance = mock_settings_cls.return_value
        mock_instance.api_url = "http://mock"
        mock_instance.api_key = "mock_key"

        async for c in get_client():
            assert "Authorization" not in c.headers
            assert "test_cookie" not in c.client.cookies
            break


@respx.mock
@pytest.mark.asyncio
async def test_get_bom_error():
    settings = DTSettings(
        DTVP_VULNERABILITY_BACKEND_API_URL="",
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


@pytest.mark.asyncio
async def test_get_current_user_profile_raises(dt_client, respx_mock):
    respx_mock.get("http://dt.example.com/api/v1/user/me").respond(status_code=401)

    with pytest.raises(httpx.HTTPStatusError):
        await dt_client.get_current_user_profile()


@pytest.mark.asyncio
async def test_get_projects_http_error(dt_client, respx_mock):
    respx_mock.get("http://dt.example.com/api/v1/project").respond(status_code=500)

    with pytest.raises(httpx.HTTPStatusError):
        await dt_client.get_projects(name="P")


@pytest.mark.asyncio
async def test_get_analysis_http_error(dt_client, respx_mock):
    respx_mock.get("http://dt.example.com/api/v1/analysis").respond(status_code=500)

    with pytest.raises(httpx.HTTPStatusError):
        await dt_client.get_analysis("p1", "c1", "v1")
