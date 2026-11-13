import json
from unittest.mock import AsyncMock, patch
import httpx
import pytest
from dtvp import main
from dtvp.code_analysis_diagnostics import safe_snapshot, save_failure_snapshot, load_failure_snapshot

@pytest.fixture(autouse=True)
def setup(monkeypatch, tmp_path):
    monkeypatch.setenv("DTVP_CODE_ANALYSIS_RESULTS_PATH", str(tmp_path / "results.sqlite"))
    monkeypatch.setenv("DTVP_CODE_ANALYSIS_URL", "http://analyzer")
    main.app.dependency_overrides[main.get_current_user] = lambda: "testuser"
    yield
    main.app.dependency_overrides.pop(main.get_current_user, None)

def test_allowlist_rejects_content_and_malformed_values():
    result = safe_snapshot("job1", {"status": [], "request": "secret", "error_details": {
        "code": [], "message": "secret", "diagnostics": {"stage": "aggregate_verdict", "exception_type": "ReadTimeout", "secret": "secret"}}})
    assert "secret" not in json.dumps(result)
    assert result["status"] == "unknown"
    assert result["error_details"]["diagnostics"]["stage"] == "aggregate_verdict"

def test_failure_snapshot_persists_and_prunes(monkeypatch):
    monkeypatch.setenv("DTVP_CODE_ANALYSIS_RESULTS_MAX_RECORDS", "1")
    save_failure_snapshot("first", {"status": "failed"})
    save_failure_snapshot("second", {"status": "failed", "error_details": {"code": "llm_unavailable"}})
    assert load_failure_snapshot("first") is None
    assert load_failure_snapshot("second")["error_details"]["code"] == "llm_unavailable"

def missing():
    return httpx.HTTPStatusError("not found", request=httpx.Request("GET", "http://analyzer"), response=httpx.Response(404))

def test_download_remote_and_saved_fallback(client):
    payload = {"job": {"status": "failed", "error_details": {"code": "llm_timeout"}}, "request": "secret"}
    with patch("dtvp.main.CodeAnalysisClient.get_job_diagnostics", AsyncMock(return_value=payload)):
        response = client.get("/api/code-analysis/jobs/job1/diagnostics")
    assert response.status_code == 200
    assert "attachment" in response.headers["content-disposition"]
    assert "secret" not in response.text
    save_failure_snapshot("job1", {"status": "failed", "error_details": {"code": "llm_unavailable"}})
    with patch("dtvp.main.CodeAnalysisClient.get_job_diagnostics", AsyncMock(side_effect=missing())):
        response = client.get("/api/code-analysis/jobs/job1/diagnostics")
        absent = client.get("/api/code-analysis/jobs/absent/diagnostics")
    assert response.json()["source"] == "dtvp_saved"
    assert absent.status_code == 404
    assert "another instance" in absent.json()["detail"]

def test_download_requires_auth(client):
    main.app.dependency_overrides.pop(main.get_current_user, None)
    response = client.get("/api/code-analysis/jobs/job1/diagnostics")
    assert response.status_code in (401, 403)


def test_report_download_is_authenticated_and_preserves_markdown(client):
    with patch("dtvp.main.CodeAnalysisClient.get_job_report", AsyncMock(return_value="# Assessment\nEvidence.")):
        response = client.get("/api/code-analysis/jobs/job1/report")
    assert response.status_code == 200
    assert response.text == "# Assessment\nEvidence."
    assert response.headers["content-type"].startswith("text/markdown")
    assert "assessment.md" in response.headers["content-disposition"]
    assert response.headers["cache-control"] == "no-store"
    main.app.dependency_overrides.pop(main.get_current_user, None)
    assert client.get("/api/code-analysis/jobs/job1/report").status_code in (401, 403)


@pytest.mark.parametrize("status,expected", [(404, 404), (409, 409), (500, 502)])
def test_report_download_failure_is_safe(client, status, expected):
    error = httpx.HTTPStatusError("PRIVATE provider body", request=httpx.Request("GET", "http://analyzer"), response=httpx.Response(status))
    with patch("dtvp.main.CodeAnalysisClient.get_job_report", AsyncMock(side_effect=error)):
        response = client.get("/api/code-analysis/jobs/job1/report")
    assert response.status_code == expected
    assert "PRIVATE" not in response.text
