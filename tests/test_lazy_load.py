import pytest
from unittest.mock import AsyncMock
from main import (
    get_assessment_details,
    AssessmentDetailsRequest,
    update_assessment,
    AssessmentRequest,
    DTClient,
)


@pytest.mark.asyncio
async def test_get_assessment_details_mock():
    # Mock client
    mock_client = AsyncMock(spec=DTClient)
    # Behave as context manager
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None

    mock_client.get_analysis.return_value = {
        "analysisState": "NOT_SET",
        "analysisDetails": "Some details",
        "isSuppressed": False,
    }

    req = AssessmentDetailsRequest(
        instances=[
            {
                "project_uuid": "p1",
                "component_uuid": "c1",
                "vulnerability_uuid": "v1",
                "finding_uuid": "f1",
            },
            {
                "project_uuid": "p2",
                "component_uuid": "c2",
                "vulnerability_uuid": "v2",
                "finding_uuid": "f2",
            },
        ]
    )

    results = await get_assessment_details(req, client=mock_client, user="test_user")

    assert len(results) == 2
    assert results[0]["analysis"]["analysisState"] == "NOT_SET"
    assert results[0]["finding_uuid"] == "f1"
    assert mock_client.get_analysis.call_count == 2


@pytest.mark.asyncio
async def test_get_assessment_details_partial_failure():
    mock_client = AsyncMock(spec=DTClient)
    # Behave as context manager
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None

    # Side effect: first success, second failure
    mock_client.get_analysis.side_effect = [
        {"analysisState": "NOT_SET"},
        Exception("DB Error"),
    ]

    req = AssessmentDetailsRequest(
        instances=[
            {
                "finding_uuid": "f1",
                "project_uuid": "p1",
                "component_uuid": "c1",
                "vulnerability_uuid": "v1",
            },
            {
                "finding_uuid": "f2",
                "project_uuid": "p2",
                "component_uuid": "c2",
                "vulnerability_uuid": "v2",
            },
        ]
    )

    results = await get_assessment_details(req, client=mock_client, user="test")

    assert len(results) == 2
    assert results[0]["analysis"] is not None
    assert results[0]["error"] is None

    assert results[1]["analysis"] is None
    assert results[1]["error"] == "DB Error"


@pytest.mark.asyncio
async def test_update_assessment_conflict():
    mock_client = AsyncMock(spec=DTClient)

    # Mock current state on server
    mock_client.get_analysis.return_value = {
        "analysisState": "EXPLOITABLE",
        "analysisDetails": "Server changed this",
        "isSuppressed": False,
    }

    # Request with stale original state
    req = AssessmentRequest(
        instances=[
            {
                "project_uuid": "p1",
                "component_uuid": "c1",
                "vulnerability_uuid": "v1",
                "finding_uuid": "f1",
                "project_name": "Pro",
                "project_version": "1.0",
                "component_name": "Comp",
            }
        ],
        state="NOT_AFFECTED",
        details="My local change",
        original_analysis={
            "f1": {
                "analysisState": "NOT_SET",
                "analysisDetails": "Original details",
                "isSuppressed": False,
            }
        },
    )

    # We expect a 409 JSONResponse
    response = await update_assessment(req, client=mock_client, user="test_user")

    # Check if response is JSONResponse (it should be)
    assert response.status_code == 409
    import json

    content = json.loads(response.body)
    assert content["status"] == "conflict"
    assert len(content["conflicts"]) == 1
    assert content["conflicts"][0]["finding_uuid"] == "f1"


@pytest.mark.asyncio
async def test_update_assessment_force():
    mock_client = AsyncMock(spec=DTClient)

    # Mock current state on server (changed)
    mock_client.get_analysis.return_value = {
        "analysisState": "EXPLOITABLE",
        "analysisDetails": "Server changed this",
        "isSuppressed": False,
    }

    req = AssessmentRequest(
        instances=[
            {
                "project_uuid": "p1",
                "component_uuid": "c1",
                "vulnerability_uuid": "v1",
                "finding_uuid": "f1",
            }
        ],
        state="NOT_AFFECTED",
        details="My local change",
        original_analysis={
            "f1": {
                "analysisState": "NOT_SET",
                "analysisDetails": "Original details",
                "isSuppressed": False,
            }
        },
        force=True,
    )

    # When force is True, we should NOT get conflict even if data changed
    # It should return list of results (status: success)
    results = await update_assessment(req, client=mock_client, user="test_user")

    assert isinstance(results, list)
    assert len(results) == 1
    assert results[0]["status"] == "success"
    # Verify update_analysis was called
    mock_client.update_analysis.assert_called_once()
