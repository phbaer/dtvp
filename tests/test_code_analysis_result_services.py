import json
import sqlite3
from contextlib import closing
from types import SimpleNamespace

import dtvp.code_analysis_result_services as result_services
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


def test_code_analysis_result_store_lists_assessments_from_dedicated_metadata(
    tmp_path,
    monkeypatch,
):
    store = CodeAnalysisResultStore(
        path_provider=lambda: str(tmp_path / "code_analysis_results.sqlite")
    )
    item = SimpleNamespace(
        queue_id="automatic-run",
        job_id="job-automatic",
        project_name="ExampleApp",
        vuln_id="CVE-2026-METADATA",
        component_name="owned-api",
        source="automatic",
        submitted_at="2026-01-03T03:00:00+00:00",
        finished_at="2026-01-03T03:04:05+00:00",
        result=None,
    )
    store.record_queue_item_result(
        item,
        {
            "assessment": {
                "affected": True,
                "verdict": "Affected",
                "analysis": "Reachable vulnerable call",
                "confidence": "high",
                "adjusted_cvss": {
                    "original_score": 8.1,
                    "original_vector": "CVSS:3.1/AV:N/AC:L/C:H",
                    "adjusted_score": 3.2,
                    "adjusted_vector": "CVSS:3.1/AV:N/AC:L/C:H/CR:L",
                    "summary": "Detailed rationale stays in the full result.",
                    "reasons": ["Runtime controls"],
                },
            },
            "llm_conversation": [{"role": "assistant", "content": "large trace"}],
        },
    )

    def fail_if_payload_is_decoded(*_args, **_kwargs):
        raise AssertionError("metadata queries must not decode full result payloads")

    monkeypatch.setattr(result_services, "_decode_record_payload", fail_if_payload_is_decoded)

    metadata = store.list_assessment_metadata(project_name="ExampleApp")

    assert metadata["stored_analysis_results"] == 1
    assert metadata["usable_assessment_results"] == 1
    assert len(metadata["records"]) == 1
    record = metadata["records"][0]
    assert record["analysis_run_id"] == "automatic-run"
    assert record["job_id"] == "job-automatic"
    assert record["vuln_id"] == "cve-2026-metadata"
    assert record["project_names"] == ["exampleapp"]
    assert record["component_names"] == ["owned-api"]
    assert record["source_kind"] == "auto"
    assert record["assessment"] == {
        "affected": True,
        "analysis": "Reachable vulnerable call",
        "confidence": "high",
        "verdict": "Affected",
        "adjusted_cvss": {
            "original_score": 8.1,
            "original_vector": "CVSS:3.1/AV:N/AC:L/C:H",
            "adjusted_score": 3.2,
            "adjusted_vector": "CVSS:3.1/AV:N/AC:L/C:H/CR:L",
        },
    }
    assert "result" not in record


def test_code_analysis_result_metadata_applies_unfiltered_limit_in_sql(
    tmp_path,
    monkeypatch,
):
    store = CodeAnalysisResultStore(
        path_provider=lambda: str(tmp_path / "code_analysis_results.sqlite")
    )
    for index in range(5):
        store.record_queue_item_result(
            SimpleNamespace(
                queue_id=f"run-{index}",
                project_name="ExampleApp",
                vuln_id=f"CVE-2026-{index}",
                component_name="owned-api",
                source="automatic",
                submitted_at=f"2026-01-03T03:0{index}:00+00:00",
                finished_at=f"2026-01-03T03:0{index}:30+00:00",
                result=None,
            ),
            {"assessment": {"verdict": "Not Affected"}},
        )

    original_decode = result_services._decode_json_strings
    decode_calls = 0

    def counted_decode(value):
        nonlocal decode_calls
        decode_calls += 1
        return original_decode(value)

    monkeypatch.setattr(result_services, "_decode_json_strings", counted_decode)

    records = store.list_result_metadata(limit=2)

    assert len(records) == 2
    assert decode_calls == 4


def test_code_analysis_result_metadata_filters_aliases_components_and_pages(tmp_path):
    store = CodeAnalysisResultStore(
        path_provider=lambda: str(tmp_path / "code_analysis_results.sqlite")
    )

    def record(run_id, vuln_id, component_name, minute):
        store.record_queue_item_result(
            SimpleNamespace(
                queue_id=run_id,
                project_name="ExampleApp",
                vuln_id=vuln_id,
                component_name=component_name,
                source="manual",
                submitted_at=f"2026-01-03T03:{minute:02d}:00+00:00",
                finished_at=f"2026-01-03T03:{minute:02d}:30+00:00",
                result=None,
            ),
            {"assessment": {"verdict": "Not Affected"}},
        )

    record("primary-service", "CVE-2026-PAGED", "owned-service", 1)
    record("alias-service", "GHSA-PAGED-ALIAS", "owned-service", 2)
    record("primary-worker", "CVE-2026-PAGED", "owned-worker", 3)
    record("other-vulnerability", "CVE-2026-OTHER", "owned-service", 4)

    first_page = store.list_result_metadata(
        project_name="ExampleApp",
        vuln_ids=["CVE-2026-PAGED", "GHSA-PAGED-ALIAS"],
        component_names=["owned-service"],
        limit=1,
    )
    second_page = store.list_result_metadata(
        project_name="ExampleApp",
        vuln_ids=["CVE-2026-PAGED", "GHSA-PAGED-ALIAS"],
        component_names=["owned-service"],
        limit=1,
        offset=1,
    )

    assert [record["analysis_run_id"] for record in first_page] == ["alias-service"]
    assert [record["analysis_run_id"] for record in second_page] == ["primary-service"]


def test_code_analysis_result_store_backfills_rescore_metadata_version(tmp_path):
    database_path = tmp_path / "code_analysis_results.sqlite"
    store = CodeAnalysisResultStore(path_provider=lambda: str(database_path))
    store.record_queue_item_result(
        SimpleNamespace(
            queue_id="automatic-rescore-run",
            project_name="ExampleApp",
            vuln_id="CVE-2026-RESCORE",
            component_name="owned-api",
            source="automatic",
            submitted_at="2026-01-03T03:00:00+00:00",
            finished_at="2026-01-03T03:04:05+00:00",
            result=None,
        ),
        {
            "assessment": {
                "affected": True,
                "verdict": "Affected",
                "adjusted_cvss": {
                    "original_score": 8.1,
                    "adjusted_score": 3.2,
                    "original_vector": "CVSS:3.1/AV:N/AC:L/C:H",
                    "adjusted_vector": "CVSS:3.1/AV:N/AC:L/C:H/CR:L",
                },
            },
            "steps": [],
        },
    )

    with closing(sqlite3.connect(database_path)) as connection:
        with connection:
            connection.execute(
                """
                UPDATE code_analysis_assessment_metadata
                SET metadata_version = 1,
                    assessment_data_json = ?
                WHERE analysis_run_id = ?
                """,
                (
                    json.dumps({"affected": True, "verdict": "Affected"}),
                    "automatic-rescore-run",
                ),
            )

    reloaded = CodeAnalysisResultStore(path_provider=lambda: str(database_path))
    metadata = reloaded.list_assessment_metadata(project_name="ExampleApp")

    assert metadata["records"][0]["assessment"]["adjusted_cvss"] == {
        "original_score": 8.1,
        "adjusted_score": 3.2,
        "original_vector": "CVSS:3.1/AV:N/AC:L/C:H",
        "adjusted_vector": "CVSS:3.1/AV:N/AC:L/C:H/CR:L",
    }


def test_code_analysis_result_store_tracks_application_provenance(tmp_path):
    store = CodeAnalysisResultStore(
        path_provider=lambda: str(tmp_path / "code_analysis_results.json")
    )
    item = SimpleNamespace(
        queue_id="auto-run",
        project_name="ExampleApp",
        vuln_id="CVE-2026-AUTO",
        component_name="owned-api",
        source="automatic",
        submitted_at="2026-01-03T03:00:00+00:00",
        finished_at="2026-01-03T03:04:05+00:00",
        result=None,
    )
    store.record_queue_item_result(
        item,
        {"assessment": {"verdict": "Not Affected", "summary": "Safe"}, "steps": []},
    )

    stored = store.record_application(
        analysis_run_id="auto-run",
        finding_uuid="finding-1",
        group_id="CVE-2026-AUTO",
        status="applied",
        applied_by="reviewer",
        workflow_id="automatic-assessments",
        payload_fingerprint="sha256:example",
    )

    assert stored["status"] == "applied"
    assert store.list_applications(
        analysis_run_ids=["auto-run"], statuses=["applied", "queued"]
    )[0] == stored
    store.record_application(
        analysis_run_id="auto-run",
        finding_uuid="finding-1",
        group_id="CVE-2026-AUTO",
        status="failed",
        applied_by="reviewer",
        workflow_id="individual-assessment",
    )
    assert store.list_applications(analysis_run_ids=["auto-run"])[0]["status"] == "applied"
    assert store.delete("auto-run") is True
    assert store.list_applications(analysis_run_ids=["auto-run"]) == []


def test_assessment_metadata_reads_are_cached_and_invalidated(tmp_path, monkeypatch):
    store = CodeAnalysisResultStore(
        path_provider=lambda: str(tmp_path / "code_analysis_results.sqlite")
    )

    def record(run_id: str, vuln_id: str) -> None:
        store.record_queue_item_result(
            SimpleNamespace(
                queue_id=run_id,
                project_name="ExampleApp",
                vuln_id=vuln_id,
                component_name="owned-api",
                source="automatic",
                submitted_at="2026-01-03T03:00:00+00:00",
                finished_at="2026-01-03T03:04:05+00:00",
                result=None,
            ),
            {
                "assessment": {
                    "affected": True,
                    "verdict": "Affected",
                }
            },
        )

    record("run-1", "CVE-2026-ONE")
    original_list = store.list_result_metadata
    calls = 0

    def counted_list(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original_list(*args, **kwargs)

    monkeypatch.setattr(store, "list_result_metadata", counted_list)

    first = store.list_assessment_metadata(project_name="ExampleApp")
    second = store.list_assessment_metadata(project_name="ExampleApp")
    record("run-2", "CVE-2026-TWO")
    third = store.list_assessment_metadata(project_name="ExampleApp")

    assert calls == 2
    assert len(first["records"]) == 1
    assert second == first
    assert len(third["records"]) == 2


def test_code_analysis_result_store_summarizes_legacy_results_for_compact_lists(tmp_path):
    legacy_path = tmp_path / "code_analysis_results.json"
    legacy_path.write_text(
        json.dumps(
            {
                "records": [
                    {
                        "analysis_run_id": "legacy-result-only",
                        "vuln_id": "CVE-2026-RESULT-ONLY",
                        "result": {
                            "assessment": {
                                "verdict": "Not Affected",
                                "summary": "Only stored in the legacy result payload",
                            }
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    store = CodeAnalysisResultStore(path_provider=lambda: str(legacy_path))

    records = store.list(limit=100, include_result=False)

    assert records[0]["summary"]["verdict"] == "Not Affected"
    assert records[0]["summary"]["summary"] == (
        "Only stored in the legacy result payload"
    )
    assert "result" not in records[0]
