import pytest
from fastapi.testclient import TestClient

from test_setup.mock_agentizer import app


@pytest.mark.parametrize("vector", [None, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"])
def test_mock_analysis_emits_eligibility_contract(vector):
    response = TestClient(app).post("/assess?sync=true", json={
        "component_name": "owned-api", "vuln_id": "CVE-test", "cvss_vector": vector,
    })
    assert response.status_code == 200
    assessment = response.json()["assessment"]
    assert assessment["application_eligible"] is True
    assert assessment["rescoring_eligible"] is bool(assessment["adjusted_cvss"])
