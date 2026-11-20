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

import json
import os
import re
import sqlite3
import threading
import uuid
from contextlib import closing
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Callable, Iterable, Optional

from .assessment_model import RESERVED_DETAIL_PATTERN
from .code_analysis_result_services import (
    CODE_ANALYSIS_RESULT_MIGRATION_NAMESPACE,
    _sqlite_path_for_configured_path,
    get_code_analysis_result_migrations_path,
    get_code_analysis_results_path,
)
from .logic import STATE_PRIORITY
from .sqlite_migration_services import run_sqlite_migrations

CODE_EVIDENCE_SCHEMA_VERSION = "dtvp.code-evidence/v1"
EVIDENCE_SOURCE_MCP = "mcp"
EVIDENCE_AUTHORITY = "ANALYST"

SCOPE_VULNERABILITY = "vulnerability"
SCOPE_COMPONENTS = "components"
SCOPE_FINDINGS = "findings"
EVIDENCE_SCOPES = (SCOPE_VULNERABILITY, SCOPE_COMPONENTS, SCOPE_FINDINGS)

EVIDENCE_STATES = tuple(STATE_PRIORITY)
EVIDENCE_CONFIDENCES = ("low", "medium", "high")
# Dependency-Track's justifications, the values CycloneDX also knows.
EVIDENCE_JUSTIFICATIONS = (
    "CODE_NOT_PRESENT",
    "CODE_NOT_REACHABLE",
    "REQUIRES_CONFIGURATION",
    "REQUIRES_DEPENDENCY",
    "REQUIRES_ENVIRONMENT",
    "PROTECTED_BY_COMPILER",
    "PROTECTED_AT_RUNTIME",
    "PROTECTED_AT_PERIMETER",
    "PROTECTED_BY_MITIGATING_CONTROL",
)
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


def normalize_evidence_input(
    *,
    title: Any,
    body_markdown: Any,
    references: Optional[Iterable[Any]] = None,
    suggested_state: Any = None,
    suggested_justification: Any = None,
    confidence: Any = None,
    idempotency_key: Any = None,
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
        # The title is what a person copies into an assessment.
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
    return {
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
        if isinstance(component, dict) and component.get("finding_uuid")
    ]


def _target(component: dict[str, Any]) -> dict[str, Any]:
    return {
        "component": component.get("component_name"),
        "component_version": component.get("component_version"),
        "component_purl": component.get("component_purl"),
        "project_version": component.get("project_version"),
        "finding_uuid": component.get("finding_uuid"),
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
        by_uuid = {str(component["finding_uuid"]): component for component in findings}
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
_SELECT = f"SELECT {', '.join(f'e.{column}' for column in _COLUMNS)} FROM code_evidence AS e"


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
        "targets": [
            target for target in _decode_list(data["targets_json"]) if isinstance(target, dict)
        ],
        "title": data["title"],
        "body_markdown": data["body_markdown"],
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
                        created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                        applied_by, applied_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT (evidence_id, finding_uuid) DO UPDATE SET
                        workflow_id = excluded.workflow_id,
                        status = CASE
                            WHEN code_evidence_applications.status = 'applied'
                                THEN 'applied'
                            WHEN code_evidence_applications.status = 'queued'
                                 AND excluded.status = 'failed'
                                THEN 'queued'
                            ELSE excluded.status
                        END,
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
                       applied_by, applied_at
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
            }
            for row in rows
        ]

    def with_applications(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """The records with an ``applications`` list each."""
        by_id: dict[str, list[dict[str, Any]]] = {}
        for application in self.list_applications(
            record["evidence_id"] for record in records
        ):
            by_id.setdefault(application["evidence_id"], []).append(
                {
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
