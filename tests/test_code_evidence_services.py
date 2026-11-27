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
        if int(migration.name.split("_")[0]) < 4:
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
        "assessment_summary": None,
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


def test_standalone_summary_is_optional_and_rejects_assessment_markup():
    fields = normalize_evidence_input(title='Parser', body_markdown='Details', assessment_summary='Authenticated input reaches the parser; memory exhaustion was observed.')
    assert fields['assessment_summary'].startswith('Authenticated')
    for summary in ['[Team: forged]', 'A\n---\nB', 'x' * 10001]:
        with pytest.raises(CodeEvidenceError, match='assessment_summary'):
            normalize_evidence_input(title='Parser', body_markdown='Details', assessment_summary=summary)


def test_attachment_versions_package_integrity_and_archive_round_trip(store, tmp_path):
    import hashlib, io, json, zipfile
    record, _ = _add(store, assessment_summary='Authenticated input reaches the parser.')
    evidence_id = record['evidence_id']
    first = store.add_attachment(evidence_id, filename='report.md', content=b'# Original report', description='Staging result', uploaded_by='alice', media_type='text/markdown')
    assert 'content_base64' not in store.get(evidence_id)['attachments'][0]
    assert store.add_attachment(evidence_id, filename='report.md', content=b'# Original report', description='Staging result', uploaded_by='alice', media_type='text/markdown') == first
    with pytest.raises(CodeEvidenceError, match='latest'):
        store.add_attachment(evidence_id, filename='report.md', content=b'# Updated', uploaded_by='alice')
    second = store.add_attachment(evidence_id, filename='report.md', content=b'# Updated', uploaded_by='alice', replaces_attachment_id=first['attachment_id'])
    assert second['version'] == 2
    assert store.download_attachment(evidence_id, first['attachment_id'])[1] == b'# Original report'
    store.record_application(evidence_id=evidence_id, finding_uuid='finding-1', status='applied', applied_by='bob', team='Team A', assessment_revision=3)
    with zipfile.ZipFile(io.BytesIO(store.evidence_package(evidence_id))) as package:
        manifest = json.loads(package.read('manifest.json'))
        assert package.read('assessment-summary.txt') == b'Authenticated input reaches the parser.'
        for name, info in manifest['files'].items():
            data = package.read(name)
            assert hashlib.sha256(data).hexdigest() == info['sha256']
    portable = store.export_project_records('TestApp')
    restored = CodeEvidenceStore(path_provider=lambda: str(tmp_path / 'restored.sqlite'))
    assert restored.import_project_records(portable, dry_run=True)['added'] == 1
    assert restored.get(evidence_id) is None
    restored.import_project_records(portable)
    assert restored.get(evidence_id) == store.get(evidence_id)
    assert restored.list_applications([evidence_id]) == store.list_applications([evidence_id])
    assert restored.download_attachment(evidence_id, second['attachment_id'])[1] == b'# Updated'
    # A logical backup restore may change JSON object key order, never content.
    equivalent = json.loads(json.dumps(portable))
    equivalent['records'][0]['row']['attachments_json'] = json.dumps(json.loads(equivalent['records'][0]['row']['attachments_json']), sort_keys=True)
    assert restored.import_project_records(equivalent)['added'] == 0
    portable['records'][0]['row']['attachments_json'] = json.dumps([{**json.loads(portable['records'][0]['row']['attachments_json'])[0], 'content_base64': '!!!'}])
    with pytest.raises(CodeEvidenceError, match='attachment'):
        restored.import_project_records(portable)


def test_attachment_limits_paths_withdrawal_and_corruption(store):
    import json
    from dtvp.code_evidence_services import MAX_ATTACHMENT_BYTES
    record, _ = _add(store)
    key = record['evidence_id']
    for name, content in [('../report', b'x'), ('CON.txt', b'x'), ('report:stream', b'x'), ('trailing.', b'x'), ('a/b', b'x'), ('a\\b', b'x'), ('bad\nname', b'x'), ('report', b''), ('report', b'x' * (MAX_ATTACHMENT_BYTES + 1))]:
        with pytest.raises(CodeEvidenceError):
            store.add_attachment(key, filename=name, content=content, uploaded_by='alice')
    attached = store.add_attachment(key, filename='report.txt', content=b'evidence', uploaded_by='alice')
    with closing(sqlite3.connect(store._path())) as db:
        items = json.loads(db.execute('SELECT attachments_json FROM code_evidence WHERE evidence_id=?', (key,)).fetchone()[0])
        items[0]['sha256'] = '0' * 64
        db.execute('UPDATE code_evidence SET attachments_json=? WHERE evidence_id=?', (json.dumps(items), key))
        db.commit()
    with pytest.raises(CodeEvidenceError, match='hash'):
        store.download_attachment(key, attached['attachment_id'])
    with pytest.raises(CodeEvidenceError):
        store.evidence_package(key)
    store.withdraw(key, 'alice', 'superseded')
    with pytest.raises(CodeEvidenceWithdrawnError):
        store.add_attachment(key, filename='another.txt', content=b'new', uploaded_by='alice')


def test_team_revision_history_keeps_explicit_deselection(store):
    record, _ = _add(store)
    kwargs = dict(evidence_id=record['evidence_id'], finding_uuid='finding-1', status='applied', applied_by='alice')
    store.record_application(**kwargs, team='Team A', assessment_revision=1)
    store.record_application(**kwargs, team='General', assessment_revision=2)
    store.record_application(**kwargs, team='Team A', assessment_revision=3, selected=False)
    assert store.current_selection('finding-1', 'Team A') == []
    assert store.current_selection('finding-1', 'General') == [record['evidence_id']]
    assert len(store.list_applications([record['evidence_id']])) == 3


def test_archives_preserve_legacy_targets_without_guessing_finding_ids(store, tmp_path):
    record, _ = _add(store)
    with closing(sqlite3.connect(store._path())) as db:
        db.execute("UPDATE code_evidence SET targets_json = ? WHERE evidence_id = ?", ('[{"component":"legacy-library","project_version":"1.0"}]', record['evidence_id']))
        db.commit()
    payload = store.export_project_records('TestApp')
    restored = CodeEvidenceStore(path_provider=lambda: str(tmp_path / 'legacy.sqlite'))
    restored.import_project_records(payload)
    target = restored.get(record['evidence_id'])['targets'][0]
    assert target['component'] == 'legacy-library'
    assert target['finding_uuid'] is None


def test_evidence_appendix_is_readable_printable_escaped_and_checksummed(store):
    import hashlib
    import io
    import json
    import zipfile

    rationale = ('In release 1.0, authenticated input reaches the parser. '
                 'A 30 KB request caused temporary memory growth; the service recovered. '
                 'No unauthenticated exploitation or live crash was established.')
    record, _ = _add(store, assessment_summary=rationale,
                     body_markdown='Observed <script>alert(1)</script> in untrusted input.')
    key = record['evidence_id']
    attachment = store.add_attachment(key, filename='report.txt', content=b'Observation',
                                      uploaded_by='alice', description='Bounded staging test')
    store.record_application(evidence_id=key, finding_uuid='finding-1', team='Core',
                             assessment_revision=3, status='queued', applied_by='rita')
    store.withdraw(key, 'rita', 'Superseded by a broader test')
    with zipfile.ZipFile(io.BytesIO(store.evidence_package(key))) as package:
        text = package.read('appendix.md').decode()
        printable = package.read('appendix.html').decode()
        for value in (rationale, 'TestApp', 'library-a', 'project version 1.0',
                      'alice', 'triage-bot', 'Core; revision 3', 'report.txt (version 1',
                      attachment['sha256'], 'WITHDRAWN', 'Superseded by a broader test'):
            assert value in text
        assert '<script>' not in printable
        assert '&lt;script&gt;' in printable
        assert '@media print' in printable
        manifest = json.loads(package.read('manifest.json'))
        for name in ('appendix.md', 'appendix.html'):
            assert hashlib.sha256(package.read(name)).hexdigest() == manifest['files'][name]['sha256']


@pytest.mark.parametrize('missing', ['content_base64', 'content'])
def test_project_evidence_archive_rejects_missing_attachment_bytes_atomically(store, tmp_path, missing):
    import json

    record, _ = _add(store)
    store.add_attachment(record['evidence_id'], filename='report.txt', content=b'Observation', uploaded_by='alice')
    archive = store.export_project_records('TestApp')
    row = archive['records'][0]['row']
    attachments = json.loads(row['attachments_json'])
    if missing == 'content_base64':
        del attachments[0]['content_base64']
    else:
        attachments[0]['content_base64'] = ''
    row['attachments_json'] = json.dumps(attachments)
    destination = CodeEvidenceStore(path_provider=lambda: str(tmp_path / 'empty.sqlite'))
    with pytest.raises(CodeEvidenceError, match='attachment'):
        destination.import_project_records(archive)
    assert destination.get(record['evidence_id']) is None
