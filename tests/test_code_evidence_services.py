"""Agent code evidence: storage, validation, and what never removes it."""

import sqlite3
from contextlib import closing
from types import SimpleNamespace

import pytest

from dtvp import main
from dtvp.code_analysis_result_services import CodeAnalysisResultStore
from dtvp.code_evidence_services import (
    MAX_ACTIVE_PER_VULNERABILITY,
    CodeEvidenceError,
    CodeEvidenceNotFoundError,
    CodeEvidenceStore,
    CodeEvidenceWithdrawnError,
    normalize_evidence_input,
    resolve_targets,
)
from dtvp.sqlite_migration_services import run_sqlite_migrations

GROUP = {
    "id": "CVE-2026-0001",
    "aliases": ["GHSA-aaaa-bbbb-cccc"],
    "affected_versions": [
        {
            "project_version": "1.0",
            "components": [
                {
                    "finding_uuid": "finding-1",
                    "project_version": "1.0",
                    "project_uuid": "p1",
                    "component_name": "library-a",
                    "component_version": "2.0",
                    "component_purl": "pkg:npm/library-a@2.0",
                    "component_uuid": "component-1",
                    "vulnerability_uuid": "vuln-1",
                },
                {
                    "finding_uuid": "finding-2",
                    "project_version": "1.0",
                    "project_uuid": "p1",
                    "component_name": "library-b",
                    "component_version": "1.1",
                    "component_uuid": "component-2",
                    "vulnerability_uuid": "vuln-1",
                },
            ],
        }
    ],
}


@pytest.fixture
def store(tmp_path):
    return CodeEvidenceStore(path_provider=lambda: str(tmp_path / "results.sqlite"))


def _add(store, *, token_id="tok_1", key=None, components=None, project="TestApp", title="Parser not linked", **overrides):
    scope, targets = resolve_targets(GROUP, components, None)
    fields = normalize_evidence_input(
        title=title,
        body_markdown="## Finding\n\nThe parser is **not** linked.",
        references=["https://example.org/commit/1"],
        suggested_state="NOT_AFFECTED",
        suggested_justification="CODE_NOT_REACHABLE",
        confidence="high",
        idempotency_key=key,
    )
    values = {
        "project_name": project,
        "vuln_id": GROUP["id"],
        "vuln_ids": [GROUP["id"], *GROUP["aliases"]],
        "scope": scope,
        "targets": targets,
        "author_username": "alice",
        "token_id": token_id,
        "agent_label": "triage-bot",
        **fields,
        **overrides,
    }
    return store.add(**values)


def test_migration_applies_to_an_existing_results_database(tmp_path):
    path = tmp_path / "results.sqlite"
    results = CodeAnalysisResultStore(path_provider=lambda: str(path))
    assert results.status()["record_count"] == 0
    with closing(sqlite3.connect(path)) as connection:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"code_evidence", "code_evidence_vuln_ids", "code_evidence_applications"} <= tables

    # A database migrated up to 0003 gains the tables on the next connect.
    from dtvp.code_analysis_result_services import get_code_analysis_result_migrations_path

    earlier = tmp_path / "earlier_migrations"
    earlier.mkdir()
    for migration in sorted(get_code_analysis_result_migrations_path().glob("*.sql")):
        if not migration.name.startswith("0004"):
            (earlier / migration.name).write_text(migration.read_text())
    old = tmp_path / "old.sqlite"
    with closing(sqlite3.connect(old)) as connection:
        run_sqlite_migrations(connection, namespace="code_analysis_results", migrations_path=earlier)
        connection.execute(
            "INSERT INTO code_analysis_results (analysis_run_id, payload_json) VALUES ('kept', '{}')"
        )
        connection.commit()
        with pytest.raises(sqlite3.OperationalError):
            connection.execute("SELECT * FROM code_evidence").fetchall()
    evidence = CodeEvidenceStore(path_provider=lambda: str(old))
    assert evidence.list_for_vulnerability("TestApp", ["CVE-2026-0001"]) == []
    with closing(sqlite3.connect(old)) as connection:
        assert connection.execute("SELECT COUNT(*) FROM code_evidence").fetchone()[0] == 0
        assert connection.execute("SELECT analysis_run_id FROM code_analysis_results").fetchall() == [("kept",)]


def test_add_get_and_list_with_aliases(store):
    record, created = _add(store)
    assert created is True
    assert record["evidence_id"].startswith("ev_")
    assert record["scope"] == "vulnerability"
    assert [t["finding_uuid"] for t in record["targets"]] == ["finding-1", "finding-2"]
    assert record["targets"][0]["component_purl"] == "pkg:npm/library-a@2.0"
    assert record["author"] == {
        "username": "alice",
        "agent_label": "triage-bot",
        "token_id": "tok_1",
        "authority": "ANALYST",
    }
    assert record["withdrawn"] is None
    assert store.get(record["evidence_id"]) == record

    by_alias = store.list_for_vulnerability("testapp", ["ghsa-aaaa-bbbb-cccc"])
    assert [r["evidence_id"] for r in by_alias] == [record["evidence_id"]]
    assert store.list_for_vulnerability("Other", ["CVE-2026-0001"]) == []
    assert store.list_for_vulnerability("TestApp", ["CVE-1999-1"]) == []


def test_component_filter_keeps_whole_vulnerability_entries(store):
    whole, _ = _add(store)
    only_b, _ = _add(store, components=["LIBRARY-B"], title="Only b")
    assert only_b["scope"] == "components"
    assert [t["component"] for t in only_b["targets"]] == ["library-b"]
    for_a = store.list_for_vulnerability("TestApp", ["CVE-2026-0001"], ["library-a"])
    assert [r["evidence_id"] for r in for_a] == [whole["evidence_id"]]
    for_b = store.list_for_vulnerability("TestApp", ["CVE-2026-0001"], ["library-b"])
    assert {r["evidence_id"] for r in for_b} == {whole["evidence_id"], only_b["evidence_id"]}


def test_idempotency_is_per_token(store):
    first, created = _add(store, key="retry-1")
    again, created_again = _add(store, key="retry-1")
    other, other_created = _add(store, key="retry-1", token_id="tok_2")
    assert created and not created_again and other_created
    assert again["evidence_id"] == first["evidence_id"]
    assert other["evidence_id"] != first["evidence_id"]


@pytest.mark.parametrize(
    "overrides",
    [
        {"project": "OtherApp"},
        {"vuln_id": "CVE-2026-9999"},
        {"components": ["library-b"]},
        {"title": "Different title"},
        {"body_markdown": "Another body"},
        {"suggested_state": "EXPLOITABLE"},
    ],
)
def test_a_reused_idempotency_key_for_different_evidence_is_rejected(store, overrides):
    first, _ = _add(store, key="k")
    with pytest.raises(CodeEvidenceError, match="already used for different evidence"):
        _add(store, key="k", **overrides)
    assert [r["evidence_id"] for r in store.list_for_vulnerability("TestApp", ["CVE-2026-0001"])] == [
        first["evidence_id"]
    ]
    assert store.list_for_vulnerability("OtherApp", ["CVE-2026-0001"]) == []


def test_active_entries_are_capped(store, monkeypatch):
    monkeypatch.setattr("dtvp.code_evidence_services.MAX_ACTIVE_PER_VULNERABILITY", 2)
    first, _ = _add(store)
    _add(store)
    with pytest.raises(CodeEvidenceError, match="withdraw entries first"):
        _add(store)
    store.withdraw(first["evidence_id"], "rita", "duplicate")
    _add(store)
    assert MAX_ACTIVE_PER_VULNERABILITY == 100


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"title": "  "}, "title is required"),
        ({"title": "x" * 161}, "limited to 160"),
        ({"title": "ok [Team: General]"}, "plain text"),
        ({"title": "ok --- forged"}, "plain text"),
        ({"title": "[State: NOT_AFFECTED"}, "plain text"),
        ({"body_markdown": "\x00\x01 "}, "body with the evidence"),
        ({"body_markdown": "x" * 20_001}, "limited to 20000"),
        ({"references": ["a"] * 0 + [f"r{i}" for i in range(21)]}, "At most 20"),
        ({"references": ["x" * 301]}, "limited to 300"),
        ({"references": ["line\nbreak"]}, "single line"),
        ({"references": "https://x"}, "list of strings"),
        ({"suggested_state": "APPROVED"}, "suggested_state"),
        ({"suggested_justification": "BECAUSE"}, "suggested_justification"),
        ({"suggested_state": "EXPLOITABLE", "suggested_justification": "CODE_NOT_REACHABLE"}, "needs suggested_state"),
        ({"confidence": "certain"}, "confidence"),
        ({"idempotency_key": "k" * 101}, "idempotency_key"),
    ],
)
def test_limits_and_enums(overrides, message):
    values = {"title": "A title", "body_markdown": "Body", **overrides}
    with pytest.raises(CodeEvidenceError, match=message):
        normalize_evidence_input(**values)


def test_input_is_cleaned():
    fields = normalize_evidence_input(
        title="Line one\nline\ttwo\x07",
        body_markdown="a\r\nb\x00\tc\x1b",
        references=[" https://x ", "https://x", ""],
        suggested_state="not_affected",
        suggested_justification="code_not_reachable",
        confidence="HIGH",
        idempotency_key=" key ",
    )
    assert fields == {
        "title": "Line one line two",
        "body_markdown": "a\nb\tc",
        "references": ["https://x"],
        "suggested_state": "NOT_AFFECTED",
        "suggested_justification": "CODE_NOT_REACHABLE",
        "confidence": "high",
        "idempotency_key": "key",
    }


def test_targets_are_resolved_against_the_group():
    scope, targets = resolve_targets(GROUP, None, ["finding-2"])
    assert scope == "findings" and [t["finding_uuid"] for t in targets] == ["finding-2"]
    with pytest.raises(CodeEvidenceError, match="Valid findings: finding-1, finding-2"):
        resolve_targets(GROUP, None, ["finding-9"])
    with pytest.raises(CodeEvidenceError, match="Valid components: library-a, library-b"):
        resolve_targets(GROUP, ["library-z"], None)


def test_withdraw_hides_and_keeps_provenance(store):
    record, _ = _add(store)
    withdrawn = store.withdraw(record["evidence_id"], "rita", "Wrong component")
    assert withdrawn["withdrawn"]["by"] == "rita"
    assert withdrawn["withdrawn"]["reason"] == "Wrong component"
    assert withdrawn["author"]["token_id"] == "tok_1"
    assert store.list_for_vulnerability("TestApp", ["CVE-2026-0001"]) == []
    assert [
        r["evidence_id"]
        for r in store.list_for_vulnerability("TestApp", ["CVE-2026-0001"], include_withdrawn=True)
    ] == [record["evidence_id"]]
    with pytest.raises(CodeEvidenceWithdrawnError):
        store.withdraw(record["evidence_id"], "rita", "again")
    with pytest.raises(CodeEvidenceNotFoundError):
        store.withdraw("ev_missing", "rita", "why")
    with pytest.raises(CodeEvidenceError, match="reason is required"):
        store.withdraw(record["evidence_id"], "rita", "  ")


def test_applications_are_recorded(store):
    record, _ = _add(store)
    store.record_application(evidence_id=record["evidence_id"], finding_uuid="finding-1", status="queued", applied_by="bob")
    [listed] = store.with_applications([record])
    assert [(a["finding_uuid"], a["status"], a["applied_by"]) for a in listed["applications"]] == [
        ("finding-1", "queued", "bob")
    ]
    with pytest.raises(ValueError):
        store.record_application(evidence_id=record["evidence_id"], finding_uuid="f", status="bogus", applied_by="bob")


def _record_run(results, run_id, finished_at):
    results.record_queue_item_result(
        SimpleNamespace(
            queue_id=run_id,
            job_id=f"job-{run_id}",
            project_name="TestApp",
            vuln_id="CVE-2026-0001",
            component_name="library-a",
            source="manual",
            submitted_at=finished_at,
            finished_at=finished_at,
            result=None,
        ),
        {"assessment": {"verdict": "Not Affected"}, "steps": []},
    )


def test_analyzer_retention_never_prunes_evidence(tmp_path, monkeypatch):
    path = str(tmp_path / "results.sqlite")
    monkeypatch.setenv("DTVP_CODE_ANALYSIS_RESULTS_MAX_RECORDS", "1")
    monkeypatch.setenv("DTVP_CODE_ANALYSIS_RESULTS_RETENTION_DAYS", "1")
    results = CodeAnalysisResultStore(path_provider=lambda: path)
    evidence = CodeEvidenceStore(path_provider=lambda: path)
    record, _ = _add(evidence)
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("UPDATE code_evidence SET created_at = '2001-01-01T00:00:00+00:00'")
        connection.commit()
    for index in range(3):
        _record_run(results, f"run-{index}", f"2026-01-0{index + 1}T00:00:00+00:00")
    assert len(results.list(project_name="TestApp")) <= 1
    assert evidence.get(record["evidence_id"]) is not None
    assert len(evidence.list_for_vulnerability("TestApp", ["CVE-2026-0001"])) == 1


def test_analyzer_cleanup_route_leaves_evidence_untouched(client):
    main.app.dependency_overrides[main.get_current_user] = lambda: "testuser"
    try:
        _record_run(main.code_analysis_result_store, "run-clean", "2026-01-02T00:00:00+00:00")
        record, _ = _add(main.code_evidence_store)
        response = client.post(
            "/api/projects/TestApp/vulnerabilities/CVE-2026-0001/analysis-cleanup",
            json={"remove_assessments": True, "remove_runs": True},
        )
        assert response.status_code == 200
        assert main.code_analysis_result_store.get("run-clean") is None
        assert main.code_evidence_store.get(record["evidence_id"])["withdrawn"] is None
    finally:
        main.app.dependency_overrides.pop(main.get_current_user, None)


def test_migrations_are_idempotent(tmp_path):
    path = tmp_path / "results.sqlite"
    store = CodeEvidenceStore(path_provider=lambda: str(path))
    _add(store)
    with closing(sqlite3.connect(path)) as connection:
        from dtvp.code_analysis_result_services import get_code_analysis_result_migrations_path

        run_sqlite_migrations(
            connection,
            namespace="code_analysis_results",
            migrations_path=get_code_analysis_result_migrations_path(),
        )
    assert len(store.list_for_vulnerability("TestApp", ["CVE-2026-0001"])) == 1
