"""Per-version sync state and content digests (ADR 0004, "Sync state" and
"Change detection").

Each read of a project version from the source is recorded on its row in
``sync_versions``: when it was attempted and succeeded, and a digest of what
the source returned. A read changes the version (``last_change_at``, a new
``generation``) only when a digest changed. A digest that was unknown (NULL,
as after the upgrade) is stored by the first read without counting a change.

This step records only; nothing is scheduled from it yet.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Mapping, Optional

KIND_FINDINGS = "findings"
KIND_VULNS = "vulns"
KIND_BOM = "bom"

STATUS_NEVER_SYNCED = "never_synced"
STATUS_SYNCED = "synced"
STATUS_FAILED = "failed"
STATUS_GONE = "gone"

ORIGIN_DT = "dt"
ORIGIN_EXPORT_ECHO = "export_echo"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _digest(items: Iterable[Any]) -> str:
    canonical = sorted(json.dumps(item, sort_keys=True, default=str) for item in items)
    return hashlib.sha256("\n".join(canonical).encode("utf-8")).hexdigest()


def _text_hash(value: Any) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()[:16]


# -- digests over the raw source payloads -------------------------------------


def finding_key(finding: Mapping[str, Any]) -> Optional[tuple[str, str]]:
    component = finding.get("component") or {}
    vulnerability = finding.get("vulnerability") or {}
    if not isinstance(component, Mapping) or not isinstance(vulnerability, Mapping):
        return None
    component_uuid = component.get("uuid")
    vulnerability_uuid = vulnerability.get("uuid")
    if not component_uuid or not vulnerability_uuid:
        return None
    return str(component_uuid), str(vulnerability_uuid)


def analysis_value(analysis: Any) -> tuple[str, str, str, str, bool]:
    """State, justification, response, details hash, suppressed."""
    analysis = analysis if isinstance(analysis, Mapping) else {}
    return (
        str(analysis.get("analysisState") or analysis.get("state") or "NOT_SET"),
        str(analysis.get("analysisJustification") or analysis.get("justification") or ""),
        str(analysis.get("analysisResponse") or analysis.get("response") or ""),
        _text_hash(
            str(analysis.get("analysisDetails") or analysis.get("details") or "").strip()
        ),
        bool(analysis.get("isSuppressed", analysis.get("suppressed", False))),
    )


def findings_digests(findings: Any) -> tuple[str, str, dict[str, str]]:
    """The findings identity digest, the analyses digest, and per finding
    key a hash of its analysis."""
    identities = []
    index: dict[str, str] = {}
    for finding in findings if isinstance(findings, list) else []:
        if not isinstance(finding, Mapping):
            continue
        key = finding_key(finding)
        if key is None:
            continue
        identities.append(key)
        index[f"{key[0]}:{key[1]}"] = _digest([analysis_value(finding.get("analysis"))])
    analyses = _digest(sorted(index.items()))
    return _digest(identities), analyses, index


def vulns_digest(vulns: Any) -> str:
    items = []
    for vuln in vulns if isinstance(vulns, list) else []:
        if not isinstance(vuln, Mapping):
            continue
        items.append(
            (
                str(vuln.get("uuid") or vuln.get("vulnId") or ""),
                str(vuln.get("severity") or ""),
                str(vuln.get("cvssV3BaseScore") or ""),
                str(vuln.get("cvssV2BaseScore") or ""),
                str(vuln.get("epssScore") or ""),
                _text_hash(
                    json.dumps(
                        [vuln.get("description"), vuln.get("references")],
                        sort_keys=True,
                        default=str,
                    )
                ),
            )
        )
    return _digest(items)


def bom_digest(bom: Any) -> str:
    """Components and dependency edges, without serial number or timestamp."""
    bom = bom if isinstance(bom, Mapping) else {}
    components = []
    for component in bom.get("components") or []:
        if not isinstance(component, Mapping):
            continue
        purl = component.get("purl")
        components.append(
            ("c", str(purl) if purl else f"{component.get('name')}@{component.get('version')}")
        )
    edges = []
    for dependency in bom.get("dependencies") or []:
        if not isinstance(dependency, Mapping):
            continue
        for target in dependency.get("dependsOn") or []:
            edges.append(("e", str(dependency.get("ref")), str(target)))
    return _digest(components + edges)


# -- echo classification -------------------------------------------------------


def classify_analysis_changes(
    previous: Optional[Mapping[str, str]],
    current: Mapping[str, str],
    findings: Any,
    exported_value: Callable[[str, str], Optional[tuple[str, str, bool]]],
) -> dict[str, list[str]]:
    """Which finding keys' analyses changed since the previous read, by
    origin: ``export_echo`` when the source now holds the value DTVP has on
    record (an export coming back), else ``dt``. Without a previous read
    nothing is classified."""
    result: dict[str, list[str]] = {ORIGIN_DT: [], ORIGIN_EXPORT_ECHO: []}
    if previous is None:
        return result
    by_key = {}
    for finding in findings if isinstance(findings, list) else []:
        if isinstance(finding, Mapping) and (key := finding_key(finding)):
            by_key[f"{key[0]}:{key[1]}"] = finding
    for key, value_hash in current.items():
        if key not in previous or previous[key] == value_hash:
            continue
        component_uuid, vulnerability_uuid = key.split(":", 1)
        state, _justification, _response, details_hash, suppressed = analysis_value(
            (by_key.get(key) or {}).get("analysis")
        )
        recorded = exported_value(component_uuid, vulnerability_uuid)
        if recorded is not None and (
            recorded[0] == state
            and _text_hash(str(recorded[1] or "").strip()) == details_hash
            and bool(recorded[2]) == suppressed
        ):
            result[ORIGIN_EXPORT_ECHO].append(key)
        else:
            result[ORIGIN_DT].append(key)
    return result


# -- the store -----------------------------------------------------------------

_COLUMNS = (
    "project_uuid", "product_name", "version", "active_in_dt", "status",
    "settled_status", "first_seen_at", "last_attempt_at", "last_success_at",
    "last_change_at", "consecutive_failures", "next_due_at", "last_error_class",
    "last_error", "dt_last_bom_import", "dt_last_vuln_analysis",
    "findings_digest", "analyses_digest", "vulns_digest", "bom_digest",
    "analyses_changed_in_dt", "analyses_export_echoes", "generation",
    "staged_generation", "requested_at", "requested_by", "request_id",
)
_DIGEST_COLUMNS = {
    KIND_FINDINGS: ("findings_digest", "analyses_digest"),
    KIND_VULNS: ("vulns_digest",),
    KIND_BOM: ("bom_digest",),
}


class SyncStateStore:
    """``sync_versions`` in the local store's database. ``connection`` returns
    this thread's connection of the local store (which runs the migration)."""

    def __init__(self, connection: Callable[[], sqlite3.Connection]) -> None:
        self._connection = connection

    def _row(self, connection: sqlite3.Connection, project_uuid: str) -> Optional[dict]:
        row = connection.execute(
            f"SELECT {', '.join(_COLUMNS)}, analyses_index_json FROM sync_versions "
            "WHERE project_uuid = ?",
            (project_uuid,),
        ).fetchone()
        if row is None:
            return None
        return dict(zip((*_COLUMNS, "analyses_index_json"), row))

    def _ensure(self, connection: sqlite3.Connection, project_uuid: str, at: str) -> dict:
        connection.execute(
            "INSERT OR IGNORE INTO sync_versions (project_uuid, first_seen_at) VALUES (?, ?)",
            (project_uuid, at),
        )
        return self._row(connection, project_uuid)  # type: ignore[return-value]

    def record_project_list(
        self, projects: Any, *, complete: bool = True, at: Optional[str] = None
    ) -> None:
        """The source's project list: new versions become ``never_synced``,
        inactive ones ``gone``, and, from a ``complete`` list, missing ones
        too; the list signals (``dtvpSourceMarks``) are stored."""
        at = at or _now()
        listed = {}
        for project in projects if isinstance(projects, list) else []:
            if isinstance(project, Mapping) and project.get("uuid"):
                listed[str(project["uuid"])] = project
        connection = self._connection()
        with connection:
            for project_uuid, project in listed.items():
                row = self._ensure(connection, project_uuid, at)
                active = project.get("active", True) is not False
                # The source adapter's change signals (dtvp/ports.py).
                marks = project.get("dtvpSourceMarks") or {}
                marks = marks if isinstance(marks, Mapping) else {}
                status = row["status"]
                if not active:
                    status = STATUS_GONE
                elif status == STATUS_GONE:
                    status = (
                        STATUS_SYNCED if row["last_success_at"] else STATUS_NEVER_SYNCED
                    )
                connection.execute(
                    """
                    UPDATE sync_versions SET product_name = ?, version = ?,
                        active_in_dt = ?, status = ?, settled_status = ?,
                        dt_last_bom_import = ?, dt_last_vuln_analysis = ?
                    WHERE project_uuid = ?
                    """,
                    (
                        project.get("name"),
                        project.get("version"),
                        1 if active else 0,
                        status,
                        status,
                        _signal(marks.get("bom")),
                        _signal(marks.get("analysis")),
                        project_uuid,
                    ),
                )
            if not complete:
                return
            placeholders = ",".join("?" for _ in listed) or "''"
            connection.execute(
                f"""
                UPDATE sync_versions SET status = ?, settled_status = ?, active_in_dt = 0
                WHERE project_uuid NOT IN ({placeholders}) AND status != ?
                """,
                (STATUS_GONE, STATUS_GONE, *listed.keys(), STATUS_GONE),
            )

    def record_read(
        self,
        project_uuid: str,
        kind: str,
        digests: tuple[str, ...],
        *,
        at: Optional[str] = None,
        analyses_index: Optional[Mapping[str, str]] = None,
        origins: Optional[Mapping[str, list[str]]] = None,
    ) -> bool:
        """A successful read of one kind. Returns whether its content changed
        (a known digest differs); that bumps the generation."""
        at = at or _now()
        columns = _DIGEST_COLUMNS[kind]
        connection = self._connection()
        with connection:
            row = self._ensure(connection, project_uuid, at)
            changed = any(
                row[column] is not None and row[column] != digest
                for column, digest in zip(columns, digests)
            )
            first = row["last_success_at"] is None
            assignments = {column: digest for column, digest in zip(columns, digests)}
            if analyses_index is not None:
                origins = origins or {}
                assignments["analyses_index_json"] = json.dumps(analyses_index)
                assignments["analyses_changed_in_dt"] = len(origins.get(ORIGIN_DT, []))
                assignments["analyses_export_echoes"] = len(
                    origins.get(ORIGIN_EXPORT_ECHO, [])
                )
                # An analysis echo of DTVP's own export is not a change in
                # the source.
                if (
                    row["findings_digest"] == digests[0]
                    and row["analyses_digest"] is not None
                    and row["analyses_digest"] != digests[1]
                    and not origins.get(ORIGIN_DT)
                ):
                    changed = False
            status = row["status"] if row["status"] == STATUS_GONE else STATUS_SYNCED
            assignments.update(
                status=status,
                settled_status=status,
                last_attempt_at=at,
                last_success_at=at,
                consecutive_failures=0,
                last_error_class=None,
                last_error=None,
            )
            if changed or first:
                assignments["generation"] = int(row["generation"] or 0) + 1
                assignments["last_change_at"] = at
            connection.execute(
                f"UPDATE sync_versions SET {', '.join(f'{name} = ?' for name in assignments)} "
                "WHERE project_uuid = ?",
                (*assignments.values(), project_uuid),
            )
        return changed

    def previous_analyses_index(self, project_uuid: str) -> Optional[dict[str, str]]:
        """Per finding key, the analysis hash of the last findings read, or
        ``None`` when it is unknown."""
        row = self._connection().execute(
            "SELECT analyses_index_json, analyses_digest FROM sync_versions "
            "WHERE project_uuid = ?",
            (project_uuid,),
        ).fetchone()
        if row is None or not row[0] or row[1] is None:
            return None
        return json.loads(row[0])

    def record_failure(
        self, project_uuid: str, error: BaseException, *, at: Optional[str] = None
    ) -> None:
        at = at or _now()
        connection = self._connection()
        with connection:
            row = self._ensure(connection, project_uuid, at)
            status = row["status"] if row["status"] == STATUS_GONE else STATUS_FAILED
            connection.execute(
                """
                UPDATE sync_versions SET status = ?, settled_status = ?,
                    last_attempt_at = ?, consecutive_failures = consecutive_failures + 1,
                    last_error_class = ?, last_error = ?
                WHERE project_uuid = ?
                """,
                (status, status, at, type(error).__name__, str(error)[:500], project_uuid),
            )

    def list_versions(
        self, *, product: Optional[str] = None, changed_since: Optional[str] = None
    ) -> list[dict[str, Any]]:
        query = f"SELECT {', '.join(_COLUMNS)} FROM sync_versions"
        clauses, params = [], []
        if product:
            clauses.append("lower(product_name) = lower(?)")
            params.append(product)
        if changed_since:
            clauses.append("last_change_at > ?")
            params.append(changed_since)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY product_name, version"
        rows = self._connection().execute(query, params).fetchall()
        return [_public(dict(zip(_COLUMNS, row))) for row in rows]

    def status(self) -> dict[str, Any]:
        connection = self._connection()
        counts = dict(
            connection.execute(
                "SELECT status, COUNT(*) FROM sync_versions GROUP BY status"
            ).fetchall()
        )
        last_success, last_change = connection.execute(
            "SELECT MAX(last_success_at), MAX(last_change_at) FROM sync_versions"
        ).fetchone()
        return {
            # No scheduler yet: reads happen in the cache refresh.
            "scheduler": "refresh",
            "versions": sum(counts.values()),
            "by_status": counts,
            "last_success_at": last_success,
            "last_change_at": last_change,
        }


def _signal(value: Any) -> Optional[str]:
    return None if value in (None, "") else str(value)


def _public(row: dict[str, Any]) -> dict[str, Any]:
    row["active_in_dt"] = bool(row["active_in_dt"])
    return row
