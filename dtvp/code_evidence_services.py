"""Code evidence written by agents through MCP (see the ADR on agent code
evidence and docs/ai-access.md).

Evidence is what an agent found in the code for one vulnerability of one
project: a title, a Markdown body, references, and optionally a suggested
decision. It is never an assessment. A person reads it in the UI and decides
whether to reference it in an assessment draft; saving that assessment
records the use here as an application.

The entries live beside the analyzer results, in the same SQLite file and
migration namespace, but in their own tables: analyzer retention and the
analyzer cleanup never touch them. Withdrawing is a soft delete that keeps
the provenance.
"""

import base64
import hashlib
import io
import json
import zipfile
import os
import re
import sqlite3
import threading
import uuid
from contextlib import closing
from dataclasses import dataclass, field
from datetime import UTC, datetime
from html import escape
from typing import Any, Callable, Iterable, Optional

from .finding_keys import instance_finding_key
from .assessment_model import ANALYSIS_JUSTIFICATIONS, RESERVED_DETAIL_PATTERN
from .code_analysis_result_services import (
    CODE_ANALYSIS_RESULT_MIGRATION_NAMESPACE,
    _sqlite_path_for_configured_path,
    get_code_analysis_result_migrations_path,
    get_code_analysis_results_path,
)
from .logic import STATE_PRIORITY
from .sqlite_migration_services import run_sqlite_migrations

MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024
MAX_ATTACHMENT_TOTAL_BYTES = 50 * 1024 * 1024
MAX_ATTACHMENTS = 20
MAX_SUMMARY_LENGTH = 10000

CODE_EVIDENCE_SCHEMA_VERSION = "dtvp.code-evidence/v1"
EVIDENCE_SOURCE_MCP = "mcp"
EVIDENCE_AUTHORITY = "ANALYST"

SCOPE_VULNERABILITY = "vulnerability"
SCOPE_COMPONENTS = "components"
SCOPE_FINDINGS = "findings"
EVIDENCE_SCOPES = (SCOPE_VULNERABILITY, SCOPE_COMPONENTS, SCOPE_FINDINGS)

EVIDENCE_STATES = tuple(STATE_PRIORITY)
EVIDENCE_CONFIDENCES = ("low", "medium", "high")
EVIDENCE_JUSTIFICATIONS = ANALYSIS_JUSTIFICATIONS
APPLICATION_STATUSES = ("applied", "queued", "failed")

MAX_TITLE_LENGTH = 160
MAX_BODY_LENGTH = 20_000
MAX_REFERENCES = 20
MAX_REFERENCE_LENGTH = 300
MAX_IDEMPOTENCY_KEY_LENGTH = 100
MAX_WITHDRAW_REASON_LENGTH = 500
MAX_ACTIVE_PER_VULNERABILITY = 100

# Every control character except tab and newline, plus DEL.
_BODY_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_ANY_CONTROL = re.compile(r"[\x00-\x1f\x7f]")

TARGET_KEYS = (
    "component",
    "component_version",
    "component_purl",
    "project_version",
    "finding_uuid",
    "project_uuid",
    "component_uuid",
    "vulnerability_uuid",
)


class CodeEvidenceError(ValueError):
    """Input that breaks an evidence rule; the message says how to fix it."""


class CodeEvidenceNotFoundError(LookupError):
    """No evidence with this id."""


class CodeEvidenceWithdrawnError(CodeEvidenceError):
    """The evidence is already withdrawn."""


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _text(value: Any) -> str:
    return str(value or "").strip()


def _single_line(value: Any) -> str:
    """Control characters (including line breaks) become spaces; runs of
    whitespace collapse to one."""
    return " ".join(_ANY_CONTROL.sub(" ", str(value or "")).split())


def clean_body(value: Any) -> str:
    text = str(value or "").replace("\r\n", "\n").replace("\r", "\n")
    return _BODY_CONTROL.sub("", text).strip()


def validate_attachment_filename(filename: str) -> None:
    if (not filename or len(filename) > 180 or filename in {'.', '..'}
        or filename[-1:] in {'.', ' '}
        or any(char in filename for char in '/\\<>:"|?*')
        or _ANY_CONTROL.search(filename)
        or re.match(r'(?i)^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)', filename)):
        raise CodeEvidenceError('Use a portable filename without paths or reserved characters (at most 180 characters)')


def normalize_evidence_input(
    *,
    title: Any,
    body_markdown: Any,
    references: Optional[Iterable[Any]] = None,
    suggested_state: Any = None,
    suggested_justification: Any = None,
    confidence: Any = None,
    idempotency_key: Any = None,
    assessment_summary: Any = None,
) -> dict[str, Any]:
    """Validate and clean the caller's fields; raise CodeEvidenceError."""
    clean_title = _single_line(title)
    if not clean_title:
        raise CodeEvidenceError("A title is required")
    if len(clean_title) > MAX_TITLE_LENGTH:
        raise CodeEvidenceError(
            f"The title is limited to {MAX_TITLE_LENGTH} characters"
        )
    if RESERVED_DETAIL_PATTERN.search(clean_title):
        # Legacy clients copied titles into assessment references.
        raise CodeEvidenceError(
            "The title must be plain text: remove '---' separators and "
            "bracketed tags such as [Team: ...] or [State: ...]"
        )

    body = clean_body(body_markdown)
    if not body:
        raise CodeEvidenceError("A Markdown body with the evidence is required")
    if len(body) > MAX_BODY_LENGTH:
        raise CodeEvidenceError(
            f"The body is limited to {MAX_BODY_LENGTH} characters"
        )

    if references is not None and not isinstance(references, (list, tuple)):
        raise CodeEvidenceError("references must be a list of strings")
    clean_references: list[str] = []
    for reference in references or []:
        if not isinstance(reference, str):
            raise CodeEvidenceError("references must be a list of strings")
        if "\n" in reference.strip() or "\r" in reference.strip():
            raise CodeEvidenceError("Each reference must be a single line")
        cleaned = _single_line(reference)
        if not cleaned:
            continue
        if len(cleaned) > MAX_REFERENCE_LENGTH:
            raise CodeEvidenceError(
                f"Each reference is limited to {MAX_REFERENCE_LENGTH} characters"
            )
        if cleaned not in clean_references:
            clean_references.append(cleaned)
    if len(clean_references) > MAX_REFERENCES:
        raise CodeEvidenceError(f"At most {MAX_REFERENCES} references are allowed")

    state = _text(suggested_state).upper() or None
    if state is not None and state not in EVIDENCE_STATES:
        raise CodeEvidenceError(
            f"suggested_state must be one of: {', '.join(EVIDENCE_STATES)}"
        )
    justification = _text(suggested_justification).upper() or None
    if justification == "NOT_SET":
        justification = None
    if justification is not None:
        if justification not in EVIDENCE_JUSTIFICATIONS:
            raise CodeEvidenceError(
                "suggested_justification must be one of: "
                f"{', '.join(EVIDENCE_JUSTIFICATIONS)}"
            )
        if state != "NOT_AFFECTED":
            raise CodeEvidenceError(
                "suggested_justification needs suggested_state NOT_AFFECTED"
            )
    level = _text(confidence).lower() or None
    if level is not None and level not in EVIDENCE_CONFIDENCES:
        raise CodeEvidenceError(
            f"confidence must be one of: {', '.join(EVIDENCE_CONFIDENCES)}"
        )
    key = _single_line(idempotency_key) or None
    if key is not None and len(key) > MAX_IDEMPOTENCY_KEY_LENGTH:
        raise CodeEvidenceError(
            f"idempotency_key is limited to {MAX_IDEMPOTENCY_KEY_LENGTH} characters"
        )
    summary = clean_body(assessment_summary) or None
    if summary and (len(summary) > MAX_SUMMARY_LENGTH or RESERVED_DETAIL_PATTERN.search(summary)):
        raise CodeEvidenceError("assessment_summary must be plain assessment prose, at most 10000 characters, without reserved tags or separators")
    return {
        "assessment_summary": summary,
        "title": clean_title,
        "body_markdown": body,
        "references": clean_references,
        "suggested_state": state,
        "suggested_justification": justification,
        "confidence": level,
        "idempotency_key": key,
    }


def _group_components(group: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        component
        for version in group.get("affected_versions") or []
        for component in version.get("components") or []
        if isinstance(component, dict) and instance_finding_key(component)
    ]


def _target(component: dict[str, Any]) -> dict[str, Any]:
    return {
        "component": component.get("component_name"),
        "component_version": component.get("component_version"),
        "component_purl": component.get("component_purl"),
        "project_version": component.get("project_version"),
        "finding_uuid": instance_finding_key(component),
        "project_uuid": component.get("project_uuid"),
        "component_uuid": component.get("component_uuid"),
        "vulnerability_uuid": component.get("vulnerability_uuid"),
    }


def _string_list(value: Any, name: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, (list, tuple)) or any(
        not isinstance(item, str) for item in value
    ):
        raise CodeEvidenceError(f"{name} must be a list of strings")
    return list(dict.fromkeys(item.strip() for item in value if item.strip()))


def resolve_targets(
    group: dict[str, Any],
    components: Optional[Iterable[str]] = None,
    finding_uuids: Optional[Iterable[str]] = None,
) -> tuple[str, list[dict[str, Any]]]:
    """The scope and the findings evidence is about, resolved against the
    server's own group: unknown values are rejected, never stored."""
    findings = _group_components(group)
    if not findings:
        raise CodeEvidenceError("This vulnerability has no findings")
    wanted_findings = _string_list(finding_uuids, "finding_uuids")
    wanted_components = _string_list(components, "components")
    if wanted_findings:
        by_uuid = {str(instance_finding_key(component)): component for component in findings}
        unknown = [uuid_ for uuid_ in wanted_findings if uuid_ not in by_uuid]
        if unknown:
            raise CodeEvidenceError(
                "These findings do not belong to this vulnerability: "
                f"{', '.join(unknown)}. Valid findings: {', '.join(sorted(by_uuid))}"
            )
        return SCOPE_FINDINGS, [_target(by_uuid[uuid_]) for uuid_ in wanted_findings]
    if wanted_components:
        names = {
            str(component.get("component_name") or "").casefold(): str(
                component.get("component_name") or ""
            )
            for component in findings
        }
        unknown = [name for name in wanted_components if name.casefold() not in names]
        if unknown:
            raise CodeEvidenceError(
                "These components are not affected by this vulnerability: "
                f"{', '.join(unknown)}. Valid components: "
                f"{', '.join(sorted(set(names.values())))}"
            )
        selected = {name.casefold() for name in wanted_components}
        return SCOPE_COMPONENTS, [
            _target(component)
            for component in findings
            if str(component.get("component_name") or "").casefold() in selected
        ]
    return SCOPE_VULNERABILITY, [_target(component) for component in findings]


def _decode_list(value: Any) -> list[Any]:
    try:
        decoded = json.loads(str(value or "[]"))
    except (TypeError, ValueError):
        return []
    return decoded if isinstance(decoded, list) else []


_COLUMNS = (
    "assessment_summary",
    "attachments_json",
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
    "created_at",
    "withdrawn_at",
    "withdrawn_by",
    "withdrawn_reason",
)
# A replay with the same token and idempotency key must carry exactly these
# values; otherwise the key is being reused for different evidence.
_REPLAY_COLUMNS = (
    "assessment_summary",
    "project_name_lower",
    "vuln_id",
    "scope",
    "targets_json",
    "title",
    "body_markdown",
    "references_json",
    "suggested_state",
    "suggested_justification",
    "confidence",
)
# Listing evidence must never materialize every attachment body. SQLite strips
# base64 content before returning the row; dedicated downloads read the bytes.
_SELECT_COLUMNS = [
    "(SELECT COALESCE(json_group_array(json_remove(value, '$.content_base64')), '[]') FROM json_each(e.attachments_json)) AS attachments_json"
    if column == 'attachments_json' else f'e.{column}' for column in _COLUMNS
]
_SELECT = f"SELECT {', '.join(_SELECT_COLUMNS)} FROM code_evidence AS e"


def _row_record(row: tuple[Any, ...], vuln_ids: list[str]) -> dict[str, Any]:
    data = dict(zip(_COLUMNS, row))
    withdrawn = (
        {
            "at": data["withdrawn_at"],
            "by": data["withdrawn_by"],
            "reason": data["withdrawn_reason"],
        }
        if data["withdrawn_at"]
        else None
    )
    return {
        "kind": "agent",
        "evidence_id": data["evidence_id"],
        "schema_version": data["schema_version"],
        "source": data["source"],
        "project_name": data["project_name"],
        "vuln_id": data["vuln_id"],
        "vuln_ids": vuln_ids,
        "scope": data["scope"],
        # Targets written before findings had a key carry none: derive it.
        "targets": [
            {**target, "finding_uuid": instance_finding_key(target)}
            for target in _decode_list(data["targets_json"]) if isinstance(target, dict)
        ],
        "title": data["title"],
        "body_markdown": data["body_markdown"],
        "assessment_summary": data["assessment_summary"],
        "attachments": [{k: v for k, v in item.items() if k != "content_base64"} for item in _decode_list(data["attachments_json"])],
        "references": [
            str(reference) for reference in _decode_list(data["references_json"])
        ],
        "suggested_state": data["suggested_state"],
        "suggested_justification": data["suggested_justification"],
        "confidence": data["confidence"],
        "author": {
            "username": data["author_username"],
            "agent_label": data["agent_label"],
            "token_id": data["token_id"],
            "authority": data["authority"],
        },
        "created_at": data["created_at"],
        "withdrawn": withdrawn,
    }


def evidence_component_names(record: dict[str, Any]) -> set[str]:
    return {
        str(target.get("component") or "").casefold()
        for target in record.get("targets") or []
        if target.get("component")
    }


@dataclass
class CodeEvidenceStore:
    path_provider: Callable[[], str] = get_code_analysis_results_path
    logger: Any = None
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False)

    def reset(self) -> None:
        """Nothing is cached; kept for symmetry with the result store."""

    def _path(self) -> str:
        return _sqlite_path_for_configured_path(self.path_provider())

    def _connect(self) -> sqlite3.Connection:
        path = self._path()
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        connection = sqlite3.connect(path, timeout=5)
        run_sqlite_migrations(
            connection,
            namespace=CODE_ANALYSIS_RESULT_MIGRATION_NAMESPACE,
            migrations_path=get_code_analysis_result_migrations_path(),
            logger=self.logger,
        )
        return connection

    @staticmethod
    def _vuln_ids(connection: sqlite3.Connection, evidence_ids: list[str]) -> dict[str, list[str]]:
        if not evidence_ids:
            return {}
        placeholders = ",".join("?" for _ in evidence_ids)
        rows = connection.execute(
            f"""
            SELECT evidence_id, vuln_id_lower FROM code_evidence_vuln_ids
            WHERE evidence_id IN ({placeholders})
            ORDER BY vuln_id_lower
            """,
            evidence_ids,
        ).fetchall()
        result: dict[str, list[str]] = {}
        for evidence_id, vuln_id in rows:
            result.setdefault(evidence_id, []).append(vuln_id)
        return result

    def _get_locked(
        self, connection: sqlite3.Connection, evidence_id: str
    ) -> Optional[dict[str, Any]]:
        row = connection.execute(
            f"{_SELECT} WHERE e.evidence_id = ?", (evidence_id,)
        ).fetchone()
        if row is None:
            return None
        return _row_record(row, self._vuln_ids(connection, [evidence_id]).get(evidence_id, []))

    def add(
        self,
        *,
        project_name: str,
        vuln_id: str,
        vuln_ids: Iterable[str],
        scope: str,
        targets: list[dict[str, Any]],
        title: str,
        body_markdown: str,
        references: list[str],
        suggested_state: Optional[str],
        suggested_justification: Optional[str],
        confidence: Optional[str],
        author_username: str,
        token_id: str,
        agent_label: str,
        authority: str = EVIDENCE_AUTHORITY,
        idempotency_key: Optional[str] = None,
        source: str = EVIDENCE_SOURCE_MCP,
        assessment_summary: Optional[str] = None,
    ) -> tuple[dict[str, Any], bool]:
        """Store one entry. Returns ``(record, created)``; a repeat with the
        same token, idempotency key and content returns the first record. The
        same key with a different project, vulnerability, targets or content
        raises ``CodeEvidenceError``."""
        if scope not in EVIDENCE_SCOPES:
            raise CodeEvidenceError(f"Unknown scope '{scope}'")
        project = _text(project_name)
        group_id = _text(vuln_id)
        if not project or not group_id:
            raise CodeEvidenceError("A project and a vulnerability are required")
        if not _text(author_username) or not _text(token_id):
            raise CodeEvidenceError("The author and the token are required")
        all_ids = sorted(
            {
                lowered
                for lowered in (_text(value).lower() for value in [group_id, *vuln_ids])
                if lowered
            }
        )
        clean_targets = [
            {key: target.get(key) for key in TARGET_KEYS} for target in targets
        ]
        with self._lock, closing(self._connect()) as connection:
            connection.isolation_level = None
            connection.execute("BEGIN IMMEDIATE")
            try:
                if idempotency_key:
                    existing = connection.execute(
                        f"SELECT evidence_id, {', '.join(_REPLAY_COLUMNS)} "
                        "FROM code_evidence "
                        "WHERE token_id = ? AND idempotency_key = ?",
                        (token_id, idempotency_key),
                    ).fetchone()
                    if existing:
                        requested = (
                            assessment_summary,
                            project.lower(),
                            group_id,
                            scope,
                            json.dumps(clean_targets, sort_keys=True),
                            title,
                            body_markdown,
                            json.dumps(list(references)),
                            suggested_state,
                            suggested_justification,
                            confidence,
                        )
                        if tuple(existing[1:]) != requested:
                            raise CodeEvidenceError(
                                "idempotency_key already used for different evidence"
                            )
                        record = self._get_locked(connection, existing[0])
                        connection.execute("COMMIT")
                        return record, False
                placeholders = ",".join("?" for _ in all_ids)
                active = connection.execute(
                    f"""
                    SELECT COUNT(DISTINCT e.evidence_id)
                    FROM code_evidence AS e
                    JOIN code_evidence_vuln_ids AS v ON v.evidence_id = e.evidence_id
                    WHERE e.project_name_lower = ?
                      AND e.withdrawn_at IS NULL
                      AND v.vuln_id_lower IN ({placeholders})
                    """,
                    [project.lower(), *all_ids],
                ).fetchone()[0]
                if int(active) >= MAX_ACTIVE_PER_VULNERABILITY:
                    raise CodeEvidenceError(
                        f"This vulnerability already has {MAX_ACTIVE_PER_VULNERABILITY} "
                        "active evidence entries in this project; withdraw "
                        "entries first"
                    )
                evidence_id = f"ev_{uuid.uuid4().hex}"
                created_at = _utc_now_iso()
                connection.execute(
                    """
                    INSERT INTO code_evidence (
                        evidence_id, schema_version, source, project_name,
                        project_name_lower, vuln_id, scope, targets_json, title,
                        body_markdown, references_json, suggested_state,
                        suggested_justification, confidence, author_username,
                        token_id, agent_label, authority, idempotency_key,
                        created_at, assessment_summary
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        evidence_id,
                        CODE_EVIDENCE_SCHEMA_VERSION,
                        source,
                        project,
                        project.lower(),
                        group_id,
                        scope,
                        json.dumps(clean_targets, sort_keys=True),
                        title,
                        body_markdown,
                        json.dumps(list(references)),
                        suggested_state,
                        suggested_justification,
                        confidence,
                        author_username,
                        token_id,
                        agent_label,
                        authority,
                        idempotency_key,
                        created_at,
                        assessment_summary,
                    ),
                )
                connection.executemany(
                    "INSERT INTO code_evidence_vuln_ids (evidence_id, vuln_id_lower) VALUES (?, ?)",
                    [(evidence_id, value) for value in all_ids],
                )
                record = self._get_locked(connection, evidence_id)
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise
        return record, True

    def get(self, evidence_id: str) -> Optional[dict[str, Any]]:
        key = _text(evidence_id)
        if not key:
            return None
        with self._lock, closing(self._connect()) as connection:
            return self._get_locked(connection, key)

    def list_for_vulnerability(
        self,
        project_name: str,
        vuln_ids: Iterable[str],
        component_names: Optional[Iterable[str]] = None,
        include_withdrawn: bool = False,
    ) -> list[dict[str, Any]]:
        """Entries for a project and any of the ids, newest first. With
        ``component_names`` only entries about those components, plus the
        ones about the whole vulnerability."""
        ids = sorted({_text(value).lower() for value in vuln_ids if _text(value)})
        project = _text(project_name).lower()
        if not ids or not project:
            return []
        placeholders = ",".join("?" for _ in ids)
        withdrawn_sql = "" if include_withdrawn else "AND e.withdrawn_at IS NULL"
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(
                f"""
                {_SELECT}
                WHERE e.project_name_lower = ?
                  {withdrawn_sql}
                  AND e.evidence_id IN (
                      SELECT evidence_id FROM code_evidence_vuln_ids
                      WHERE vuln_id_lower IN ({placeholders})
                  )
                ORDER BY e.created_at DESC, e.evidence_id DESC
                """,
                [project, *ids],
            ).fetchall()
            vuln_ids_by_id = self._vuln_ids(connection, [row[0] for row in rows])
        records = [_row_record(row, vuln_ids_by_id.get(row[0], [])) for row in rows]
        wanted = {
            str(name).casefold() for name in component_names or [] if _text(name)
        }
        if wanted:
            records = [
                record
                for record in records
                if record["scope"] == SCOPE_VULNERABILITY
                or not wanted.isdisjoint(evidence_component_names(record))
            ]
        return records

    def withdraw(self, evidence_id: str, by: str, reason: str) -> dict[str, Any]:
        cleaned_reason = _single_line(reason)
        if not cleaned_reason:
            raise CodeEvidenceError("A reason is required to withdraw evidence")
        if len(cleaned_reason) > MAX_WITHDRAW_REASON_LENGTH:
            raise CodeEvidenceError(
                f"The reason is limited to {MAX_WITHDRAW_REASON_LENGTH} characters"
            )
        key = _text(evidence_id)
        with self._lock, closing(self._connect()) as connection:
            connection.isolation_level = None
            connection.execute("BEGIN IMMEDIATE")
            try:
                record = self._get_locked(connection, key)
                if record is None:
                    raise CodeEvidenceNotFoundError(key)
                if record["withdrawn"]:
                    raise CodeEvidenceWithdrawnError("This evidence is already withdrawn")
                connection.execute(
                    """
                    UPDATE code_evidence
                    SET withdrawn_at = ?, withdrawn_by = ?, withdrawn_reason = ?
                    WHERE evidence_id = ?
                    """,
                    (_utc_now_iso(), _text(by), cleaned_reason, key),
                )
                record = self._get_locked(connection, key)
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise
        return record

    def record_application(
        self,
        *,
        evidence_id: str,
        finding_uuid: str,
        status: str,
        applied_by: str,
        workflow_id: str = "",
        team: str = "",
        assessment_revision: int = -1,
        selected: bool = True,
    ) -> dict[str, Any]:
        key = _text(evidence_id)
        finding = _text(finding_uuid)
        normalized_status = _text(status).lower()
        if not key or not finding:
            raise ValueError("Evidence id and finding uuid are required")
        if normalized_status not in APPLICATION_STATUSES:
            raise ValueError(f"Unsupported application status: {status}")
        application = {
            "evidence_id": key,
            "finding_uuid": finding,
            "team": team,
            "assessment_revision": assessment_revision,
            "selected": selected,
            "workflow_id": _text(workflow_id),
            "status": normalized_status,
            "applied_by": _text(applied_by),
            "applied_at": _utc_now_iso(),
        }
        with self._lock, closing(self._connect()) as connection:
            with connection:
                connection.execute(
                    """
                    INSERT INTO code_evidence_applications (
                        evidence_id, finding_uuid, workflow_id, status,
                        applied_by, applied_at, team, assessment_revision, selected
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT (evidence_id, finding_uuid, team, assessment_revision) DO UPDATE SET
                        workflow_id = excluded.workflow_id,
                        status = CASE
                            WHEN code_evidence_applications.status = 'applied'
                                THEN 'applied'
                            WHEN code_evidence_applications.status = 'queued'
                                 AND excluded.status = 'failed'
                                THEN 'queued'
                            ELSE excluded.status
                        END,
                        selected = excluded.selected,
                        applied_by = excluded.applied_by,
                        applied_at = excluded.applied_at
                    """,
                    (
                        key,
                        finding,
                        application["workflow_id"],
                        normalized_status,
                        application["applied_by"],
                        application["applied_at"],
                        team,
                        assessment_revision,
                        int(selected),
                    ),
                )
        return application

    def list_applications(self, evidence_ids: Iterable[str]) -> list[dict[str, Any]]:
        ids = list(dict.fromkeys(_text(value) for value in evidence_ids if _text(value)))
        if not ids:
            return []
        placeholders = ",".join("?" for _ in ids)
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(
                f"""
                SELECT evidence_id, finding_uuid, workflow_id, status,
                       applied_by, applied_at, team, assessment_revision, selected
                FROM code_evidence_applications
                WHERE evidence_id IN ({placeholders})
                ORDER BY applied_at DESC, evidence_id, finding_uuid
                """,
                ids,
            ).fetchall()
        return [
            {
                "evidence_id": row[0],
                "finding_uuid": row[1],
                "workflow_id": row[2],
                "status": row[3],
                "applied_by": row[4],
                "applied_at": row[5],
                "team": row[6],
                "assessment_revision": row[7],
                "selected": bool(row[8]),
            }
            for row in rows
        ]

    def has_applications(self, finding_uuids: Iterable[str]) -> bool:
        """One cheap lookup avoids per-team/finding work on ordinary saves."""
        findings = list(dict.fromkeys(finding_uuids))
        if not findings:
            return False
        with self._lock, closing(self._connect()) as db:
            for offset in range(0, len(findings), 500):
                chunk = findings[offset:offset + 500]
                if db.execute('SELECT 1 FROM code_evidence_applications WHERE finding_uuid IN (' + ','.join('?' for _ in chunk) + ') LIMIT 1', chunk).fetchone():
                    return True
        return False

    def current_selection(self, finding_uuid: str, team: str) -> list[str]:
        with self._lock, closing(self._connect()) as db:
            rows = db.execute("""SELECT a.evidence_id, a.selected FROM code_evidence_applications a
                WHERE a.finding_uuid = ? AND a.team = ? AND a.assessment_revision = (
                    SELECT MAX(b.assessment_revision) FROM code_evidence_applications b
                    WHERE b.finding_uuid = a.finding_uuid AND b.team = a.team
                )""", (finding_uuid, team)).fetchall()
        return [row[0] for row in rows if row[1]]

    def with_applications(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """The records with an ``applications`` list each."""
        by_id: dict[str, list[dict[str, Any]]] = {}
        for application in self.list_applications(
            record["evidence_id"] for record in records
        ):
            by_id.setdefault(application["evidence_id"], []).append(
                {
                    "team": application["team"],
                    "assessment_revision": application["assessment_revision"],
                    "selected": application["selected"],
                    "finding_uuid": application["finding_uuid"],
                    "status": application["status"],
                    "applied_by": application["applied_by"],
                    "applied_at": application["applied_at"],
                }
            )
        return [
            {**record, "applications": by_id.get(record["evidence_id"], [])}
            for record in records
        ]

    def add_attachment(
        self, evidence_id: str, *, filename: str, content: bytes,
        uploaded_by: str, description: str = "", media_type: str = "application/octet-stream",
        replaces_attachment_id: str | None = None,
    ) -> dict[str, Any]:
        """Append an immutable file version; bytes and provenance commit together."""
        validate_attachment_filename(filename)
        if not content or len(content) > MAX_ATTACHMENT_BYTES:
            raise CodeEvidenceError("Attachments must contain 1 byte to 10 MiB")
        if len(description) > 2000 or not _text(uploaded_by):
            raise CodeEvidenceError("An uploader and a description of at most 2000 characters are required")
        if not re.fullmatch(r"[a-zA-Z0-9.+-]+/[a-zA-Z0-9.+-]+", media_type):
            raise CodeEvidenceError("Invalid media type")
        digest = hashlib.sha256(content).hexdigest()
        with self._lock, closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                record = self._get_locked(db, evidence_id)
                if record is None:
                    raise CodeEvidenceNotFoundError(evidence_id)
                if record['withdrawn']:
                    raise CodeEvidenceWithdrawnError("Withdrawn evidence cannot receive attachments")
                items = json.loads(db.execute("SELECT attachments_json FROM code_evidence WHERE evidence_id = ?", (evidence_id,)).fetchone()[0])
                validate_attachments(items)
                same_name = [item for item in items if item['filename'] == filename]
                previous = same_name[-1] if same_name else None
                if previous and previous['sha256'] == digest and previous['description'] == description and previous['media_type'] == media_type:
                    db.rollback()
                    return {k: v for k, v in previous.items() if k != 'content_base64'}
                if (previous and replaces_attachment_id != previous['attachment_id']) or (not previous and replaces_attachment_id):
                    raise CodeEvidenceError("A new version must name the latest attachment it replaces")
                if len(items) >= MAX_ATTACHMENTS or sum(item['size'] for item in items) + len(content) > MAX_ATTACHMENT_TOTAL_BYTES:
                    raise CodeEvidenceError("Evidence is limited to 20 attachment versions and 50 MiB total")
                attachment = {
                    'attachment_id': f"att_{uuid.uuid4().hex}", 'filename': filename,
                    'description': description, 'media_type': media_type, 'size': len(content),
                    'sha256': digest, 'uploaded_by': uploaded_by, 'uploaded_at': _utc_now_iso(),
                    'version': previous['version'] + 1 if previous else 1,
                    'replaces_attachment_id': replaces_attachment_id,
                    'content_base64': base64.b64encode(content).decode('ascii'),
                }
                items.append(attachment)
                db.execute("UPDATE code_evidence SET attachments_json = ? WHERE evidence_id = ?", (json.dumps(items), evidence_id))
                db.commit()
            except BaseException:
                db.rollback()
                raise
        return {k: v for k, v in attachment.items() if k != 'content_base64'}

    def attachment_records(self, evidence_id: str) -> list[dict[str, Any]]:
        with self._lock, closing(self._connect()) as db:
            row = db.execute("SELECT attachments_json FROM code_evidence WHERE evidence_id = ?", (evidence_id,)).fetchone()
        if row is None:
            raise CodeEvidenceNotFoundError(evidence_id)
        items = json.loads(row[0])
        validate_attachments(items)
        return items

    def download_attachment(self, evidence_id: str, attachment_id: str) -> tuple[dict[str, Any], bytes]:
        item = next((item for item in self.attachment_records(evidence_id) if item['attachment_id'] == attachment_id), None)
        if item is None:
            raise CodeEvidenceNotFoundError(attachment_id)
        return {k: v for k, v in item.items() if k != 'content_base64'}, base64.b64decode(item['content_base64'], validate=True)

    @staticmethod
    def _evidence_appendix(record: dict[str, Any], items: list[dict[str, Any]]) -> str:
        """Portable, readable provenance; never invent an assessment or approval."""
        author = record['author']
        lines = [
            '# Evidence appendix', '', record['title'], '',
            f"Project: {record['project_name']}",
            f"Vulnerabilities: {', '.join(record['vuln_ids'])}",
            f"Recorded: {record['created_at']}",
            f"Author: {author['username']} via {author['agent_label']} ({author['authority']})",
            f"Scope: {record['scope']}",
            'Evidence supports a decision; it is not a reviewer approval.',
        ]
        if record.get('withdrawn'):
            withdrawal = record['withdrawn']
            lines += [f"WITHDRAWN: {withdrawal['by']} at {withdrawal['at']}: {withdrawal['reason']}"]
        lines += ['', '## Consumer and release scope']
        for target in record['targets']:
            lines += [f"- {target.get('component') or 'Unknown component'} "
                      f"{target.get('component_version') or ''}; project version "
                      f"{target.get('project_version') or 'not recorded'}"]
        lines += ['', '## Assessment rationale', '', record.get('assessment_summary')
                  or 'No assessment summary recorded. An author must write a standalone rationale before applying this evidence.',
                  '', '## Source report', '', record['body_markdown']]
        if record['references']:
            lines += ['', '## References', *[f'- {value}' for value in record['references']]]
        lines += ['', '## Supporting files']
        for item in items:
            lines += [f"- {item['filename']} (version {item['version']}, {item['size']} bytes, {item['media_type']})",
                      f"  Uploaded by {item['uploaded_by']} at {item['uploaded_at']}",
                      f"  SHA-256: {item['sha256']}", f"  {item['description']}"]
        if not items:
            lines += ['No supporting files recorded.']
        lines += ['', '## Assessment use history', 'Historical associations; these do not imply approval.']
        for application in record.get('applications', []):
            revision = application.get('assessment_revision', -1)
            lines += [f"- {application.get('team') or 'Team not recorded (legacy)'}; "
                      f"revision {revision if revision >= 0 else 'not recorded'}; "
                      f"{'selected' if application.get('selected', True) else 'deselected'}; "
                      f"{application['status']}; {application['applied_by']} at {application['applied_at']}; "
                      f"finding {application['finding_uuid']}"]
        if not record.get('applications'):
            lines += ['No assessment use recorded.']
        return '\n'.join(lines) + '\n'

    def evidence_package(self, evidence_id: str) -> bytes:
        record = self.get(evidence_id)
        if record is None:
            raise CodeEvidenceNotFoundError(evidence_id)
        record = self.with_applications([record])[0]
        items = self.attachment_records(evidence_id)
        appendix = self._evidence_appendix(record, items)
        # Source reports and filenames are untrusted. The printable HTML is
        # escaped text with no scripts, active links or external resources.
        printable = ('<!doctype html><html lang="en"><meta charset="utf-8">'
                     '<meta name="viewport" content="width=device-width,initial-scale=1">'
                     '<title>Evidence appendix</title>'
                     '<style>body{font:12pt/1.5 sans-serif;max-width:70rem;margin:2rem}'
                     'pre{font:inherit;white-space:pre-wrap;overflow-wrap:anywhere}'
                     '@media print{body{margin:0}}</style><body><pre>'
                     + escape(appendix) + '</pre></body></html>')
        files = {'appendix.md': appendix.encode(), 'appendix.html': printable.encode(), 'evidence.json': json.dumps(record, indent=2).encode(), 'report.md': record['body_markdown'].encode()}
        if record.get('assessment_summary'):
            files['assessment-summary.txt'] = record['assessment_summary'].encode()
        for item in items:
            files[f"attachments/{item['attachment_id']}/{item['filename']}"] = base64.b64decode(item['content_base64'], validate=True)
        manifest = {name: {'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)} for name, data in files.items()}
        files['manifest.json'] = json.dumps({'schema': 'dtvp.evidence-package/1', 'files': manifest}, indent=2).encode()
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
            for name, data in files.items():
                archive.writestr(name, data)
        return buffer.getvalue()


    def export_project_records(self, project_name: str, versions: list[str] | None = None) -> dict[str, Any]:
        with self._lock, closing(self._connect()) as db:
            db.row_factory = sqlite3.Row
            rows = []
            total_bytes = 0
            for stored in db.execute('SELECT * FROM code_evidence WHERE project_name_lower = ? ORDER BY evidence_id', (project_name.lower(),)):
                row = dict(stored)
                if versions is not None and not any(target.get('project_version') in versions for target in json.loads(row['targets_json'])):
                    continue
                total_bytes += len(row['attachments_json'].encode())
                if total_bytes > 128 * 1024 * 1024:
                    raise CodeEvidenceError('Project evidence exceeds the 128 MiB archive limit; use an instance backup')
                rows.append(row)
            records = []
            for row in rows:
                validate_attachments(json.loads(row['attachments_json']))
                records.append({'row': row, 'vuln_ids': [item[0] for item in db.execute('SELECT vuln_id_lower FROM code_evidence_vuln_ids WHERE evidence_id = ? ORDER BY vuln_id_lower', (row['evidence_id'],))]})
        applications = self.list_applications(row['row']['evidence_id'] for row in records)
        return {'schema': 'dtvp.project-evidence/1', 'project_name': project_name, 'records': records, 'applications': applications}

    def import_project_records(self, payload: dict[str, Any], *, dry_run: bool = False) -> dict[str, int]:
        if payload.get('schema') != 'dtvp.project-evidence/1' or not isinstance(payload.get('records'), list) or not isinstance(payload.get('applications'), list):
            raise CodeEvidenceError('Unsupported project evidence payload')
        with self._lock, closing(self._connect()) as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                columns = [row[1] for row in db.execute('PRAGMA table_info(code_evidence)')]
                ids = set()
                added = 0
                for item in payload['records']:
                    row = item['row']
                    if set(row) != set(columns) or row['project_name'] != payload['project_name'] or row['project_name_lower'] != payload['project_name'].lower():
                        raise CodeEvidenceError('Invalid archived evidence identity')
                    normalize_evidence_input(title=row['title'], body_markdown=row['body_markdown'], assessment_summary=row['assessment_summary'], references=json.loads(row['references_json']), suggested_state=row['suggested_state'], suggested_justification=row['suggested_justification'], confidence=row['confidence'], idempotency_key=row['idempotency_key'])
                    targets = json.loads(row['targets_json'])
                    if row['scope'] not in EVIDENCE_SCOPES or not isinstance(targets, list) or not targets or not all(isinstance(t, dict) for t in targets):
                        raise CodeEvidenceError('Invalid archived evidence targets')
                    validate_attachments(json.loads(row['attachments_json']))
                    if row['evidence_id'] in ids:
                        raise CodeEvidenceError('Duplicate archived evidence id')
                    ids.add(row['evidence_id'])
                    current = db.execute('SELECT ' + ','.join(columns) + ' FROM code_evidence WHERE evidence_id = ?', (row['evidence_id'],)).fetchone()
                    if current:
                        current_values = dict(zip(columns, current))
                        def source_targets(raw):
                            targets = json.loads(raw)
                            for target in targets:
                                source = target.pop('archive_source', {})
                                target.update(source)
                            return json.dumps(targets, sort_keys=True)
                        original = {**row, 'targets_json': source_targets(row['targets_json'])}
                        existing = {**current_values, 'targets_json': source_targets(current_values['targets_json'])}
                        for column in ('attachments_json', 'references_json'):
                            original[column] = json.dumps(json.loads(original[column]), sort_keys=True)
                            existing[column] = json.dumps(json.loads(existing[column]), sort_keys=True)
                        if original != existing:
                            raise CodeEvidenceError('An existing evidence id has different archived content')
                        continue
                    db.execute('INSERT INTO code_evidence (' + ','.join(columns) + ') VALUES (' + ','.join('?' for _ in columns) + ')', [row[key] for key in columns])
                    db.executemany('INSERT INTO code_evidence_vuln_ids VALUES (?, ?)', [(row['evidence_id'], value) for value in item['vuln_ids']])
                    added += 1
                for app in payload['applications']:
                    if app['evidence_id'] not in ids or app['status'] not in APPLICATION_STATUSES:
                        raise CodeEvidenceError('Invalid archived evidence application')
                    columns_app = ['evidence_id','finding_uuid','team','assessment_revision','workflow_id','status','applied_by','applied_at','selected']
                    values = {**app, 'team': app.get('team', ''), 'assessment_revision': app.get('assessment_revision', -1), 'selected': int(app.get('selected', True))}
                    current = db.execute('SELECT ' + ','.join(columns_app) + ' FROM code_evidence_applications WHERE evidence_id=? AND finding_uuid=? AND team=? AND assessment_revision=?', (values['evidence_id'], values['finding_uuid'], values['team'], values['assessment_revision'])).fetchone()
                    incoming = tuple(values[key] for key in columns_app)
                    if current and tuple(current) != incoming:
                        raise CodeEvidenceError('An existing evidence association has different archived content')
                    if not current:
                        db.execute('INSERT INTO code_evidence_applications (' + ','.join(columns_app) + ') VALUES (' + ','.join('?' for _ in columns_app) + ')', incoming)
                if dry_run:
                    db.rollback()
                else:
                    db.commit()
            except BaseException:
                db.rollback()
                raise
        return {'evidence_records': len(ids), 'added': added, 'associations': len(payload['applications'])}


def validate_attachments(items: list[dict[str, Any]]) -> None:
    """Reject incomplete or corrupt supporting material on download and restore."""
    if not isinstance(items, list) or len(items) > MAX_ATTACHMENTS:
        raise CodeEvidenceError("Invalid attachment inventory")
    total = 0
    seen = set()
    latest: dict[str, dict[str, Any]] = {}
    for item in items:
        try:
            name = item['filename']
            if not isinstance(name, str):
                raise ValueError('invalid filename')
            validate_attachment_filename(name)
            content = base64.b64decode(item['content_base64'], validate=True)
            if not content or len(content) > MAX_ATTACHMENT_BYTES or len(content) != item['size'] or hashlib.sha256(content).hexdigest() != item['sha256']:
                raise ValueError('size or hash mismatch')
            if item['attachment_id'] in seen or not re.fullmatch(r'att_[a-f0-9]{32}', item['attachment_id']):
                raise ValueError('invalid attachment id')
            previous = latest.get(name)
            if item['version'] != (previous['version'] + 1 if previous else 1) or item.get('replaces_attachment_id') != (previous['attachment_id'] if previous else None):
                raise ValueError('broken version chain')
            if not isinstance(item['description'], str) or len(item['description']) > 2000 or not _text(item['uploaded_by']) or not _text(item['uploaded_at']) or not re.fullmatch(r'[a-zA-Z0-9.+-]+/[a-zA-Z0-9.+-]+', item['media_type']):
                raise ValueError('invalid provenance')
            seen.add(item['attachment_id'])
            latest[name] = item
            total += len(content)
        except (KeyError, TypeError, ValueError) as exc:
            raise CodeEvidenceError(f"Invalid evidence attachment: {exc}") from exc
    if total > MAX_ATTACHMENT_TOTAL_BYTES:
        raise CodeEvidenceError('Evidence attachments exceed 50 MiB')
