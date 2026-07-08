import json
from types import SimpleNamespace

from dtvp.code_analysis_result_services import CodeAnalysisResultStore


def test_code_analysis_result_store_imports_legacy_json_and_writes_sqlite(tmp_path):
    legacy_path = tmp_path / "code_analysis_results.json"
    legacy_path.write_text(
        json.dumps(
            {
                "records": [
                    {
                        "analysis_run_id": "legacy-run",
                        "queue_id": "legacy-run",
                        "project_name": "ExampleApp",
                        "vuln_id": "CVE-2026-LEGACY",
                        "component_name": "owned-api",
                        "source": "automatic",
                        "context_fingerprint": "legacy-fingerprint",
                        "finished_at": "2026-01-02T03:04:05+00:00",
                        "submitted_at": "2026-01-02T03:00:00+00:00",
                        "summary": {"verdict": "Not Affected"},
                        "result": {"assessment": {"summary": "Legacy result"}},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    store = CodeAnalysisResultStore(path_provider=lambda: str(legacy_path))

    imported = store.get("legacy-run")
    assert imported is not None
    assert imported["result"]["assessment"]["summary"] == "Legacy result"
    assert store.find_latest(
        project_name="ExampleApp",
        vuln_id="CVE-2026-LEGACY",
        component_name="owned-api",
        source="automatic",
        context_fingerprint="legacy-fingerprint",
    )["analysis_run_id"] == "legacy-run"

    item = SimpleNamespace(
        queue_id="new-run",
        job_id="job-new",
        project_name="ExampleApp",
        vuln_id="CVE-2026-LEGACY",
        component_name="owned-api",
        source="manual",
        submitted_at="2026-01-03T03:00:00+00:00",
        started_at="2026-01-03T03:01:00+00:00",
        finished_at="2026-01-03T03:04:05+00:00",
        result=None,
    )
    store.record_queue_item_result(
        item,
        {
            "assessment": {
                "affected": False,
                "verdict": "Not Affected",
                "summary": "SQLite result",
            },
            "steps": [],
        },
    )

    assert (tmp_path / "code_analysis_results.sqlite").exists()
    listed = store.list(project_name="ExampleApp", vuln_id="CVE-2026-LEGACY")
    assert [record["analysis_run_id"] for record in listed] == [
        "new-run",
        "legacy-run",
    ]
    assert "result" not in listed[0]
    assert store.get("new-run")["result"]["assessment"]["summary"] == "SQLite result"
    assert store.status()["storage"] == "sqlite"
