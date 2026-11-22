"""The entities of ``dtvp.dump/1``, where they come from, and what happens
to every table and column of the databases (``COLUMN_MAP``)."""

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from ..access_token_services import (
    ACCESS_TOKEN_MIGRATION_NAMESPACE,
    get_access_token_migrations_path,
)
from ..assessment_outbox_services import (
    ASSESSMENT_OUTBOX_MIGRATION_NAMESPACE,
    get_assessment_outbox_migrations_path,
)
from ..code_analysis_result_services import (
    CODE_ANALYSIS_RESULT_MIGRATION_NAMESPACE,
    get_code_analysis_result_migrations_path,
)
from ..finding_lifecycle_services import (
    FINDING_LIFECYCLE_MIGRATION_NAMESPACE,
    get_finding_lifecycle_migrations_path,
)
from ..local_store import LOCAL_STORE_MIGRATION_NAMESPACE, get_local_store_migrations_path
from .schemas import ENTITY_ORDER

# Where the code's migrations of each namespace live.
MIGRATION_PATHS: dict[str, Callable[[], Path]] = {
    LOCAL_STORE_MIGRATION_NAMESPACE: get_local_store_migrations_path,
    ASSESSMENT_OUTBOX_MIGRATION_NAMESPACE: get_assessment_outbox_migrations_path,
    ACCESS_TOKEN_MIGRATION_NAMESPACE: get_access_token_migrations_path,
    CODE_ANALYSIS_RESULT_MIGRATION_NAMESPACE: get_code_analysis_result_migrations_path,
    FINDING_LIFECYCLE_MIGRATION_NAMESPACE: get_finding_lifecycle_migrations_path,
}

GROUP_RECORD = "record"
GROUP_SOURCE = "source"
GROUP_CREDENTIALS = "credentials"


def _key(record: dict[str, Any]) -> tuple[str, str, str]:
    key = record["key"]
    return (key["project_uuid"], key["component_uuid"], key["vulnerability_uuid"])


@dataclass(frozen=True)
class EntitySpec:
    name: str
    # The migration namespace of the table, or None for a record file.
    namespace: str | None
    table: str | None
    group: str
    natural_key: Callable[[dict[str, Any]], Any]


ENTITIES: dict[str, EntitySpec] = {
    spec.name: spec
    for spec in (
        EntitySpec("assessment", ASSESSMENT_OUTBOX_MIGRATION_NAMESPACE, "assessment_state", GROUP_RECORD, _key),
        EntitySpec("revision", ASSESSMENT_OUTBOX_MIGRATION_NAMESPACE, "assessment_revisions", GROUP_RECORD, lambda r: r["revision_id"]),
        EntitySpec("outbox_entry", ASSESSMENT_OUTBOX_MIGRATION_NAMESPACE, "assessment_outbox", GROUP_RECORD, _key),
        EntitySpec("known_project", LOCAL_STORE_MIGRATION_NAMESPACE, "known_projects", GROUP_RECORD, lambda r: r["project_uuid"]),
        EntitySpec("source_snapshot", LOCAL_STORE_MIGRATION_NAMESPACE, "source_snapshots", GROUP_SOURCE, lambda r: (r["kind"], r["project_uuid"])),
        EntitySpec("source_project", LOCAL_STORE_MIGRATION_NAMESPACE, "source_projects", GROUP_SOURCE, lambda r: r["position"]),
        EntitySpec("source_finding", LOCAL_STORE_MIGRATION_NAMESPACE, "source_findings", GROUP_SOURCE, lambda r: (r["project_uuid"], r["position"])),
        EntitySpec("source_project_vulnerability", LOCAL_STORE_MIGRATION_NAMESPACE, "source_project_vulnerabilities", GROUP_SOURCE, lambda r: (r["project_uuid"], r["position"])),
        EntitySpec("source_bom", LOCAL_STORE_MIGRATION_NAMESPACE, "source_boms", GROUP_SOURCE, lambda r: r["project_uuid"]),
        EntitySpec("source_analysis", LOCAL_STORE_MIGRATION_NAMESPACE, "source_analyses", GROUP_SOURCE, _key),
        EntitySpec("token_audit", ACCESS_TOKEN_MIGRATION_NAMESPACE, "access_token_audit", GROUP_RECORD, lambda r: r["audit_id"]),
        EntitySpec("access_token", ACCESS_TOKEN_MIGRATION_NAMESPACE, "access_tokens", GROUP_CREDENTIALS, lambda r: r["token_id"]),
        EntitySpec("code_analysis_result", CODE_ANALYSIS_RESULT_MIGRATION_NAMESPACE, "code_analysis_results", GROUP_RECORD, lambda r: r["analysis_run_id"]),
        EntitySpec("code_analysis_application", CODE_ANALYSIS_RESULT_MIGRATION_NAMESPACE, "code_analysis_result_applications", GROUP_RECORD, lambda r: (r["analysis_run_id"], r["finding_uuid"])),
        EntitySpec("code_evidence", CODE_ANALYSIS_RESULT_MIGRATION_NAMESPACE, "code_evidence", GROUP_RECORD, lambda r: r["evidence_id"]),
        EntitySpec("code_evidence_application", CODE_ANALYSIS_RESULT_MIGRATION_NAMESPACE, "code_evidence_applications", GROUP_RECORD, lambda r: (r["evidence_id"], r["finding_uuid"])),
        EntitySpec("finding_presence", FINDING_LIFECYCLE_MIGRATION_NAMESPACE, "finding_presence", GROUP_RECORD, _key),
        EntitySpec("finding_read", FINDING_LIFECYCLE_MIGRATION_NAMESPACE, "finding_reads", GROUP_RECORD, lambda r: r["project_uuid"]),
        EntitySpec("session_version", ACCESS_TOKEN_MIGRATION_NAMESPACE, "session_versions", GROUP_RECORD, lambda r: r["username"]),
        EntitySpec("tmrescore_proposal", None, None, GROUP_RECORD, lambda r: r["project_name"]),
        EntitySpec("instance_metadata", LOCAL_STORE_MIGRATION_NAMESPACE, "store_metadata", GROUP_RECORD, lambda r: r["key"]),
    )
}
assert tuple(ENTITIES) == ENTITY_ORDER

SOURCE_ENTITIES = tuple(name for name, spec in ENTITIES.items() if spec.group == GROUP_SOURCE)
# store_metadata keys kept as instance_metadata records.
INSTANCE_METADATA_KEYS = ("active_projects",)


# -- coverage map -------------------------------------------------------------
#
# Every table of every namespace, and every column of the tables that are
# dumped, says where it goes. tests/test_backup_coverage.py builds fully
# migrated databases and fails on anything not listed here.

def field(entity: str, target: str) -> str:
    return f"field: {entity}.{target}"


DERIVED = "derived: rebuilt from the records during a restore"
STORAGE = "storage: resolved on export"
LOOKUP = "lookup: rebuilt from the payload by the row functions"
CACHE = "cache: rebuilt by the backend; a restore moves the files aside"
MARKER = "marker: migration bookkeeping; a restore writes 'done' markers"

# Whole tables.
TABLE_MAP: dict[str, str] = {
    "assessment_fields": DERIVED,
    "assessment_team_fields": DERIVED,
    "code_analysis_assessment_metadata": DERIVED,
    "assessment_outbox_metadata": MARKER,
    "code_analysis_result_meta": MARKER,
    "schema_migrations": "marker: listed per store in manifest.stores[].migrations",
    # Read from Dependency-Track in the background for the VDR
    # recommendation; an empty table is read again after a restore.
    "source_vulnerability_ranges": "excluded: version ranges re-read from Dependency-Track in the background",
    "sqlite_sequence": "marker: kept as manifest.cut_point.sequences",
    # ADR 0004: the state of the reads from Dependency-Track. Derived from
    # those reads; after a restore every version is read again, which
    # rebuilds it (unknown digests are stored without counting a change).
    "sync_versions": "excluded: per-version sync state, rebuilt by the next reads from Dependency-Track",
    "finding_lifecycle_metadata": "marker: the one-time presence backfill; a restore writes it as done",
}

_KEY = {
    "project_uuid": "key.project_uuid",
    "component_uuid": "key.component_uuid",
    "vulnerability_uuid": "key.vulnerability_uuid",
}

COLUMN_MAP: dict[str, dict[str, str]] = {
    "assessment_state": {
        **{column: field("assessment", target) for column, target in _KEY.items()},
        "revision": field("assessment", "revision"),
        "analysis_state": field("assessment", "value.state"),
        "analysis_details": field("assessment", "value.details"),
        "suppressed": field("assessment", "value.suppressed"),
        "sync_status": field("assessment", "sync.status"),
        "update_id": field("assessment", "sync.update_id"),
        "last_error": field("assessment", "sync.last_error"),
        "updated_at": field("assessment", "updated_at"),
        "export_rejections": field("assessment", "sync.export_rejections"),
        "base_state": field("assessment", "sync.base.state"),
        "base_suppressed": field("assessment", "sync.base.suppressed"),
        "base_details": STORAGE + " into sync.base.details",
        "base_same": STORAGE + "; a storage hint only",
        "remote_state": field("assessment", "sync.remote.state"),
        "remote_details": field("assessment", "sync.remote.details"),
        "remote_suppressed": field("assessment", "sync.remote.suppressed"),
    },
    "assessment_revisions": {
        "revision_id": field("revision", "revision_id"),
        **{column: field("revision", target) for column, target in _KEY.items()},
        "revision": field("revision", "revision"),
        "analysis_state": field("revision", "value.state"),
        "analysis_details": field("revision", "value.details"),
        "suppressed": field("revision", "value.suppressed"),
        "origin": field("revision", "origin"),
        "author": field("revision", "author"),
        "created_at": field("revision", "created_at"),
        "text_in_record": STORAGE + " into value.details",
    },
    "assessment_outbox": {
        **{column: field("outbox_entry", target) for column, target in _KEY.items()},
        "revision": field("outbox_entry", "revision"),
        "update_id": field("outbox_entry", "update_id"),
        "payload_json": field("outbox_entry", "payload"),
        "attempts": field("outbox_entry", "attempts"),
        "next_attempt_at": field("outbox_entry", "next_attempt_at"),
        "last_error": field("outbox_entry", "last_error"),
        "created_at": field("outbox_entry", "created_at"),
        "updated_at": field("outbox_entry", "updated_at"),
    },
    "known_projects": {
        column: field("known_project", column)
        for column in ("project_uuid", "name", "version", "first_seen_at", "last_seen_at")
    },
    "store_metadata": {
        "key": field("instance_metadata", "key")
        + " (active_projects; projects_meta is a cache, legacy_json_import a marker)",
        "value_json": field("instance_metadata", "value"),
        "updated_at": "excluded: the time of the last metadata write, set again by every write",
    },
    "source_snapshots": {
        "kind": field("source_snapshot", "kind"),
        "project_uuid": field("source_snapshot", "project_uuid"),
        "item_count": field("source_snapshot", "item_count"),
        "raw_json": field("source_snapshot", "form and raw"),
        "updated_at": field("source_snapshot", "updated_at"),
    },
    "source_projects": {
        "position": field("source_project", "position"),
        "payload_json": field("source_project", "payload"),
        "project_uuid": LOOKUP,
        "name": LOOKUP,
        "version": LOOKUP,
    },
    "source_findings": {
        "project_uuid": field("source_finding", "project_uuid"),
        "position": field("source_finding", "position"),
        "payload_json": field("source_finding", "payload"),
        **{
            column: LOOKUP
            for column in (
                "component_uuid",
                "vulnerability_uuid",
                "vuln_id",
                "severity",
                "component_name",
                "component_version",
            )
        },
    },
    "source_project_vulnerabilities": {
        "project_uuid": field("source_project_vulnerability", "project_uuid"),
        "position": field("source_project_vulnerability", "position"),
        "payload_json": field("source_project_vulnerability", "payload"),
        "vulnerability_uuid": LOOKUP,
        "vuln_id": LOOKUP,
    },
    "source_boms": {
        "project_uuid": field("source_bom", "project_uuid"),
        "payload_json": field("source_bom", "payload"),
        "updated_at": field("source_bom", "updated_at"),
    },
    "source_analyses": {
        **{column: field("source_analysis", target) for column, target in _KEY.items()},
        "payload_json": field("source_analysis", "payload"),
        "updated_at": field("source_analysis", "updated_at"),
        "analysis_state": LOOKUP,
        "analysis_details": LOOKUP,
        "suppressed": LOOKUP,
    },
    "access_tokens": {
        column: field("access_token", column)
        for column in (
            "token_id",
            "username",
            "name",
            "token_hash",
            "scopes",
            "created_at",
            "expires_at",
            "last_used_at",
            "revoked_at",
        )
    },
    "access_token_audit": {
        **{
            column: field("token_audit", column)
            for column in (
                "audit_id",
                "occurred_at",
                "username",
                "token_id",
                "agent",
                "action",
                "outcome",
                "detail",
            )
        },
        "target_json": field("token_audit", "target"),
    },
    "code_analysis_results": {
        "analysis_run_id": field("code_analysis_result", "analysis_run_id"),
        "payload_json": field("code_analysis_result", "payload"),
        **{
            column: LOOKUP
            for column in (
                "project_name_lower",
                "vuln_id_lower",
                "component_name_lower",
                "source_lower",
                "context_fingerprint",
                "finished_at",
                "submitted_at",
                "recorded_at",
                "record_timestamp",
            )
        },
    },
    "code_analysis_result_applications": {
        column: field("code_analysis_application", column)
        for column in (
            "analysis_run_id",
            "finding_uuid",
            "group_id_lower",
            "workflow_id",
            "status",
            "applied_by",
            "applied_at",
            "payload_fingerprint",
        )
    },
    "code_evidence": {
        **{
            column: field("code_evidence", column.removesuffix("_json"))
            for column in (
                "evidence_id",
                "schema_version",
                "source",
                "project_name",
                "vuln_id",
                "scope",
                "targets_json",
                "title",
                "body_markdown",
                "references_json",
                "suggested_state",
                "suggested_justification",
                "confidence",
                "author_username",
                "token_id",
                "agent_label",
                "authority",
                "idempotency_key",
                "created_at",
                "withdrawn_at",
                "withdrawn_by",
                "withdrawn_reason",
            )
        },
        "project_name_lower": LOOKUP,
    },
    "code_evidence_vuln_ids": {
        "evidence_id": field("code_evidence", "evidence_id"),
        "vuln_id_lower": field("code_evidence", "vuln_ids"),
    },
    "code_evidence_applications": {
        column: field("code_evidence_application", column)
        for column in (
            "evidence_id",
            "finding_uuid",
            "workflow_id",
            "status",
            "applied_by",
            "applied_at",
        )
    },
    "finding_presence": {
        **{column: field("finding_presence", target) for column, target in _KEY.items()},
        **{
            column: field("finding_presence", column)
            for column in (
                "vuln_id",
                "component_name",
                "component_version",
                "component_purl",
                "component_identity",
                "first_seen_at",
                "status",
                "gone_at",
                "last_seen_at",
                "gone_reason",
                "successor_component_uuid",
                "carry_over",
                "returned_at",
                "acknowledged_by",
                "acknowledged_at",
                "gone_cause",
                "predates_tracking",
                "same_issue_component_uuid",
                "same_issue_vulnerability_uuid",
                "same_issue_reason",
                "same_issue_confirmed_by",
                "same_issue_confirmed_at",
            )
        },
    },
    "finding_reads": {
        "project_uuid": field("finding_read", "project_uuid"),
        "read_at": field("finding_read", "read_at"),
        "went_json": field("finding_read", "went"),
        "returned": field("finding_read", "returned"),
        "carried_over": field("finding_read", "carried_over"),
        "not_carried": field("finding_read", "not_carried"),
    },
    "session_versions": {
        column: field("session_version", column)
        for column in ("username", "version", "revoked_at")
    },
}
