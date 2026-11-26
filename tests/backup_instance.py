"""A separate DTVP instance in a temporary directory, filled through the real
stores, for tests of the instance dump. It is never the conftest instance,
whose directory the test process holds the instance lock on."""

import json
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from dtvp.access_token_services import AccessTokenStore
from dtvp.assessment_outbox_services import (
    AssessmentOutboxStore,
    get_legacy_assessment_outbox_path,
)
from dtvp.code_analysis_result_services import CodeAnalysisResultStore
from dtvp.code_evidence_services import CodeEvidenceStore
from dtvp.instance_stores import InstanceStores, resolve_instance_stores
from dtvp.local_store import (
    KIND_ANALYSIS,
    KIND_BOM,
    KIND_FINDINGS,
    KIND_METADATA,
    KIND_PROJECT_VULNERABILITIES,
    KIND_PROJECTS,
    DocumentRef,
    LocalStore,
    get_database_path,
)
from dtvp.tmrescore_cache_services import save_tmrescore_project_cache

P1 = "p0000001-0000-4000-8000-000000000001"
P2 = "p0000002-0000-4000-8000-000000000002"
GONE = "p0000009-0000-4000-8000-000000000009"


def _key(project, component, vulnerability):
    return (project, component, vulnerability)


@dataclass
class Instance:
    root: Path

    @property
    def dt_cache(self) -> Path:
        return self.root / "data" / "dt_cache"

    @property
    def database(self) -> str:
        return get_database_path(str(self.dt_cache))

    @property
    def code_analysis_results(self) -> str:
        return str(self.root / "data" / "code_analysis_results.sqlite")

    def stores(self) -> InstanceStores:
        return resolve_instance_stores()

    def outbox(self) -> AssessmentOutboxStore:
        return AssessmentOutboxStore(
            self.database,
            legacy_path=get_legacy_assessment_outbox_path(str(self.dt_cache)),
        )

    def local_store(self) -> LocalStore:
        return LocalStore(self.database)

    def code_analysis(self) -> CodeAnalysisResultStore:
        return CodeAnalysisResultStore(path_provider=lambda: self.code_analysis_results)

    def tokens(self) -> AccessTokenStore:
        return AccessTokenStore()

    def sql(self, path: str | None = None) -> sqlite3.Connection:
        return closing(sqlite3.connect(path or self.database))


ENV_UNSET = (
    "DTVP_DATABASE_PATH",
    "DTVP_ASSESSMENT_OUTBOX_PATH",
    "DTVP_ACCESS_TOKENS_PATH",
)


def configure_instance(monkeypatch, root: Path) -> Instance:
    """Point every path variable at ``root``, in the default layout."""
    data = root / "data"
    data.mkdir(parents=True, exist_ok=True)
    for variable in ENV_UNSET:
        monkeypatch.delenv(variable, raising=False)
    monkeypatch.setenv("DTVP_DT_CACHE_PATH", str(data / "dt_cache"))
    monkeypatch.setenv("DTVP_CODE_ANALYSIS_RESULTS_PATH", str(data / "code_analysis_results.sqlite"))
    monkeypatch.setenv("DTVP_TMRESCORE_CACHE_PATH", str(data / "tmrescore_proposals.json"))
    monkeypatch.setenv("DTVP_GROUPED_VULN_SUMMARY_INDEX_PATH", str(data / "grouped_vuln_summary_index.sqlite"))
    monkeypatch.setenv("DTVP_SSVC_CACHE_PATH", str(data / "dt_cache" / "ssvc_enrichment.sqlite3"))
    monkeypatch.setenv("TEAM_MAPPING_PATH", str(data / "team_mapping.json"))
    monkeypatch.setenv("TEAM_GROUPS_PATH", str(data / "team_groups.json"))
    monkeypatch.setenv("USER_ROLES_PATH", str(data / "user_roles.json"))
    monkeypatch.setenv("RESCORE_RULES_PATH", str(data / "rescore_rules.json"))
    monkeypatch.setenv("DTVP_AUTO_ANALYSIS_GUIDANCE_PATH", str(data / "auto_analysis_guidance.json"))
    monkeypatch.setenv("DTVP_BACKUP_PATH", str(root / "backups"))
    monkeypatch.setenv("DTVP_DT_API_URL", "https://user:secret@dtrack.example.test:8443/api/?apiKey=x#frag")
    (data / "dt_cache").mkdir(parents=True, exist_ok=True)
    return Instance(root)


def _text(team, state, body):
    return f"--- [Team: {team}] [State: {state}] [Assessed By: alice]\n{body}"


def populate(instance: Instance) -> dict:
    """Fill an instance with every kind of record and state."""
    store = instance.local_store()
    store.write(
        DocumentRef(KIND_PROJECTS),
        [
            {"uuid": P1, "name": "Imaging Suite", "version": "4.2"},
            {"uuid": GONE, "name": "Retired", "version": "0.9"},
        ],
    )
    # The retired project leaves the list but stays known.
    store.write(
        DocumentRef(KIND_PROJECTS),
        [
            {"uuid": P1, "name": "Imaging Suite", "version": "4.2"},
            {"uuid": P2, "name": "Viewer", "version": "1.0", "note": "ü"},
        ],
    )
    findings = [
        {
            "component": {"uuid": f"c{index}", "name": f"lib-{index}", "version": "1.0"},
            "vulnerability": {"uuid": f"v{index}", "vulnId": f"CVE-2026-{index:04d}", "severity": "HIGH"},
        }
        for index in range(1, 4)
    ]
    store.write(DocumentRef(KIND_FINDINGS, project_uuid=P1), findings)
    store.write(DocumentRef(KIND_PROJECT_VULNERABILITIES, project_uuid=P1), [{"uuid": "v1", "vulnId": "CVE-2026-0001"}])
    store.write(DocumentRef(KIND_PROJECT_VULNERABILITIES, project_uuid=P2), None)
    store.write(DocumentRef(KIND_BOM, project_uuid=P1), {"bomFormat": "CycloneDX", "components": []})
    store.write(
        DocumentRef(KIND_ANALYSIS, project_uuid=P1, component_uuid="c1", vulnerability_uuid="v1"),
        {"analysisState": "NOT_AFFECTED", "analysisDetails": "x", "isSuppressed": True},
    )
    store.write(DocumentRef(KIND_METADATA, name="active_projects"), {P1: 1763280000.25})
    store.write(DocumentRef(KIND_METADATA, name="projects_meta"), {"fully_cached": True, "revision": 4})
    store.close()

    outbox = instance.outbox()
    keys = {
        "synced": _key(P1, "c1", "v1"),
        "pending": _key(P1, "c1", "v2"),
        "error": _key(P1, "c2", "v1"),
        "inactive": _key(P1, "c3", "v3"),
        "cancelled": _key(P2, "c9", "v9"),
        "imported": _key(P2, "c8", "v8"),
        "transient": _key(P2, "c7", "v7"),
    }

    def payload(key, state, details, suppressed=False):
        return {
            "project_uuid": key[0],
            "component_uuid": key[1],
            "vulnerability_uuid": key[2],
            "state": state,
            "details": details,
            "suppressed": suppressed,
        }

    first = _text("Core", "IN_TRIAGE", "Looking into it.")
    for name in ("synced", "pending", "error", "inactive", "cancelled", "transient"):
        outbox.enqueue_many([payload(keys[name], "IN_TRIAGE", first)], author="alice")
    outbox.mark_synced(keys["synced"], 1)
    outbox.mark_synced(keys["pending"], 1)
    outbox.enqueue_many(
        [payload(keys["pending"], "EXPLOITABLE", _text("Core", "EXPLOITABLE", "Reachable."))],
        author="bob",
        origin="wf-1a2b3c4d",
    )
    outbox.mark_failed(keys["error"], 1, "HTTP 503", next_attempt_at="2026-11-20T12:00:00+00:00")
    assert outbox.drop_missing_finding(keys["inactive"], 1)
    outbox.discard_many([outbox.get_overlay(keys["cancelled"])["update_id"]], author="carol")
    outbox.mark_synced(keys["transient"], 1)
    with instance.sql() as connection, connection:
        # An assessment adopted on import: revision 0 whose history entry
        # keeps its text in the record.
        imported = _text("Viewer", "NOT_AFFECTED", "Not shipped.")
        connection.execute(
            """
            INSERT INTO assessment_state (
                project_uuid, component_uuid, vulnerability_uuid, revision,
                analysis_state, analysis_details, suppressed, sync_status,
                update_id, last_error, updated_at, base_state, base_details,
                base_suppressed, remote_state, remote_details, remote_suppressed,
                export_rejections, base_same
            ) VALUES (?, ?, ?, 0, 'NOT_AFFECTED', ?, 0, 'synced', NULL, NULL,
                      '2026-11-01T00:00:00+00:00', 'NOT_AFFECTED', NULL, 0,
                      'IN_TRIAGE', 'They say otherwise.', 1, 3, 1)
            """,
            (*keys["imported"], imported),
        )
        connection.execute(
            """
            INSERT INTO assessment_revisions (
                project_uuid, component_uuid, vulnerability_uuid, revision,
                analysis_state, analysis_details, suppressed, origin, author,
                created_at, text_in_record
            ) VALUES (?, ?, ?, 0, 'NOT_AFFECTED', '', 0, 'import', NULL,
                      '2026-11-01T00:00:00+00:00', 1)
            """,
            keys["imported"],
        )
        # The transient state a snapshot can capture: base_same set while
        # base_details still holds the old text.
        connection.execute(
            """
            UPDATE assessment_state
            SET base_same = 1, base_details = 'the text the base had'
            WHERE project_uuid = ? AND component_uuid = ? AND vulnerability_uuid = ?
            """,
            keys["transient"],
        )
        # A queued payload that is not JSON.
        connection.execute(
            "UPDATE assessment_outbox SET payload_json = '{broken' "
            "WHERE project_uuid = ? AND component_uuid = ? AND vulnerability_uuid = ?",
            keys["error"],
        )

    # Read the rows written directly into fields, as a backend start does.
    instance.outbox()._ensure_initialized()

    tokens = instance.tokens()
    token, _plain = tokens.create(username="alice", name="agent", scopes=["read", "write"])
    tokens.record_audit(token=token, agent="claude", action="list", outcome="ok", target={"project": "Imaging"})
    tokens.record_audit(token=token, agent="claude", action="save", outcome="denied", detail="read only")
    # Logout and revocation raise a user's session version.
    tokens.revoke_sessions("alice")
    tokens.revoke_sessions("alice")

    # What happened to findings: one gone and carried over, one reported.
    from dtvp.assessment_outbox_services import get_assessment_outbox_path
    from dtvp.finding_lifecycle_services import FindingLifecycleStore

    lifecycle = FindingLifecycleStore(get_assessment_outbox_path(str(instance.dt_cache)))
    base_row = {
        "vuln_id": "CVE-2026-0001",
        "component_name": "lib-1",
        "component_purl": "pkg:npm/lib-1@1.0",
        "component_identity": "pkg:npm/lib-1",
        "first_seen_at": "2026-11-01T08:00:00+00:00",
        "last_seen_at": None,
        "gone_at": None,
        "gone_reason": None,
        "successor_component_uuid": None,
        "carry_over": None,
        "returned_at": None,
    }
    lifecycle.record_read(
        "p-lifecycle",
        [
            {**base_row, "component_uuid": "c-old", "vulnerability_uuid": "v-l",
             "component_version": "1.0", "status": "gone",
             "gone_at": "2026-11-19T08:00:00+00:00",
             "last_seen_at": "2026-11-18T08:00:00+00:00", "gone_reason": "replaced",
             "successor_component_uuid": "c-new", "carry_over": "carried"},
            {**base_row, "component_uuid": "c-new", "vulnerability_uuid": "v-l",
             "component_version": "1.1", "status": "reported",
             "component_purl": "pkg:npm/lib-1@1.1",
             "first_seen_at": "2026-11-19T08:00:00+00:00"},
            {**base_row, "component_uuid": "c-new", "vulnerability_uuid": "v-cpe",
             "component_version": "1.1", "status": "gone",
             "component_purl": "pkg:npm/lib-1@1.1",
             "gone_at": "2026-11-19T08:00:00+00:00", "gone_reason": "no_longer_matched",
             "gone_cause": "CPE changed from cpe:2.3:a:x:lib:1.1 to cpe:2.3:a:y:lib:1.1",
             "first_seen_at": "", "predates_tracking": 1},
        ],
        {"read_at": "2026-11-19T08:00:00+00:00", "went": {"replaced": 1},
         "returned": 0, "carried_over": 1, "not_carried": 0},
    )
    lifecycle.acknowledge(
        "p-lifecycle", [("c-old", "v-l")], by="rita", at="2026-11-19T09:00:00+00:00"
    )
    # A gone finding a reviewer confirmed to be the same issue as a reported one.
    lifecycle.confirm_same_issue(
        "p-lifecycle", ("c-new", "v-cpe"), ("c-new", "v-l"),
        reason="same description", by="rita", at="2026-11-19T09:30:00+00:00",
    )

    results = instance.code_analysis()
    with results._lock:
        results._ensure_loaded()
        with closing(results._connect()) as connection, connection:
            results._upsert_record_locked(
                connection,
                {
                    "analysis_run_id": "run-1",
                    "project_name": "Imaging Suite",
                    "vuln_id": "CVE-2026-0001",
                    "component_name": "lib-1",
                    "source": "manual",
                    "finished_at": datetime.now(UTC).isoformat(),
                    "result": {"assessment": {"state": "NOT_AFFECTED"}},
                },
            )
    results.record_application(
        analysis_run_id="run-1",
        finding_uuid="v1",
        group_id="CVE-2026-0001",
        status="applied",
        applied_by="alice",
        workflow_id="wf-1a2b3c4d",
    )

    # Agent code evidence: record data beside the analyzer runs.
    evidence = CodeEvidenceStore(path_provider=lambda: instance.code_analysis_results)
    kept, _created = evidence.add(
        project_name="Imaging Suite",
        vuln_id="CVE-2026-0001",
        vuln_ids=["CVE-2026-0001", "GHSA-xxxx-yyyy-zzzz"],
        scope="components",
        targets=[{"component_name": "lib-1", "finding_uuid": "v1"}],
        title="Parser not reachable",
        body_markdown="The **parser** never sees user input.",
        references=["https://example.test/src/parser.py#L10"],
        suggested_state="NOT_AFFECTED",
        suggested_justification="CODE_NOT_REACHABLE",
        confidence="high",
        author_username="alice",
        token_id=token.token_id,
        agent_label="alice (via agent)",
        idempotency_key="run-42",
    )
    withdrawn, _created = evidence.add(
        project_name="Imaging Suite",
        vuln_id="CVE-2026-0001",
        vuln_ids=["CVE-2026-0001"],
        scope="vulnerability",
        targets=[],
        title="Superseded note",
        body_markdown="Wrong component.",
        references=[],
        suggested_state=None,
        suggested_justification=None,
        confidence=None,
        author_username="alice",
        token_id=token.token_id,
        agent_label="alice (via agent)",
    )
    evidence.withdraw(withdrawn["evidence_id"], "rita", "Wrong component")
    evidence.record_application(
        evidence_id=kept["evidence_id"],
        finding_uuid="v1",
        status="applied",
        applied_by="alice",
        workflow_id="individual-assessment",
    )

    # Saved views and defaults (ADR 0015).
    from dtvp.saved_view_services import SavedViewStore

    views = SavedViewStore(instance.database)
    mine = views.create(
        user="alice", role="ANALYST", name="My open", scope="personal",
        project="Imaging Suite", query="lifecycle=OPEN&cutoff=2026-11-01",
    )
    shared = views.create(
        user="rita", role="REVIEWER", name="Release 7.1", scope="global",
        project=None, query="awaiting_review=false&versions=7.1.0",
    )
    views.set_default(
        user="alice", role="ANALYST", target="user", target_role=None,
        project="Imaging Suite", code=mine.code,
    )
    views.set_default(
        user="rita", role="REVIEWER", target="role", target_role="ANALYST",
        project=None, code=shared.code,
    )
    keys["saved_views"] = (mine.code, shared.code)

    save_tmrescore_project_cache({"Imaging Suite": {"status": "completed", "proposals": [{"score": 5.3}]}})
    data = instance.root / "data"
    (data / "team_mapping.json").write_bytes(b'{"lib-1": "Core"}\n')
    (data / "team_groups.json").write_bytes(b'{"All": {"teams": ["Core"], "groups": []}}')
    (data / "rescore_rules.json").write_bytes(json.dumps({"transitions": []}).encode())
    (data / "auto_analysis_guidance.json").write_bytes(b"{}")
    return keys


def table_rows(path: str, table: str) -> list[tuple]:
    with closing(sqlite3.connect(path)) as connection:
        return connection.execute(f"SELECT * FROM {table} ORDER BY 1, 2, 3").fetchall()


def all_files(root: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }
