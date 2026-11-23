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

import contextvars
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Mapping, Optional
from uuid import uuid4

KIND_FINDINGS = "findings"
KIND_VULNS = "vulns"
KIND_BOM = "bom"

STATUS_NEVER_SYNCED = "never_synced"
STATUS_QUEUED = "queued"
STATUS_SYNCING = "syncing"
STATUS_SYNCED = "synced"
STATUS_FAILED = "failed"
STATUS_GONE = "gone"

ORIGIN_DT = "dt"
ORIGIN_EXPORT_ECHO = "export_echo"


class SourceUnavailable(RuntimeError):
    """The scheduler's circuit breaker is open: Dependency-Track is not
    called, and that is no failure of the version asked for."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _digest(items: Iterable[Any]) -> str:
    canonical = sorted(json.dumps(item, sort_keys=True, default=str) for item in items)
    return hashlib.sha256("\n".join(canonical).encode("utf-8")).hexdigest()


def _text_hash(value: Any) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()[:16]


# Set by the scheduler for the safety re-read: the findings read then takes
# every assessment's details from the source, not from the record, so an
# edit of the details alone in the source is seen (``CacheManager.
# _read_findings_list``).
FULL_ANALYSIS_DETAILS: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "dtvp_full_analysis_details", default=False
)


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


# Bumped when the digest's fields change: a recorded digest of another
# version counts as missing and is seeded again, so the change cannot make
# every version look changed for good.
PORTFOLIO_DIGEST_VERSION = "p2"


def portfolio_digest(findings: Any) -> str:
    """What a portfolio-wide findings list can tell about a version: its
    finding keys and, per finding, the analysis state and suppression.

    Only fields both reads carry the same way count. Dependency-Track 4.x
    builds both from ``Finding``, whose analysis holds only ``state`` and
    ``isSuppressed`` (``Finding.QUERY`` and ``QUERY_ALL_FINDINGS``); the
    details, justification and response of a version's own read come from
    its per-finding analysis reads, which a portfolio list does not make.
    Counting the details made every assessed version differ from its share
    of the list on every pass (ADR 0004, "Portfolio pass"). Edits of the
    details alone are seen by the regular full re-read. Suppressed findings
    are left out: the project export leaves them out (``getFindings(project)``
    is ``includeSuppressed=false``) while the list and the portfolio read
    carry them, so a suppression shows as the finding leaving the digest."""
    items = []
    for finding in findings if isinstance(findings, list) else []:
        if not isinstance(finding, Mapping):
            continue
        key = finding_key(finding)
        if key is None:
            continue
        analysis = finding.get("analysis") if isinstance(finding.get("analysis"), Mapping) else {}
        if analysis.get("isSuppressed", analysis.get("suppressed", False)):
            continue
        items.append(
            (
                key[0],
                key[1],
                str(analysis.get("analysisState") or analysis.get("state") or "NOT_SET"),
            )
        )
    return f"{PORTFOLIO_DIGEST_VERSION}:{_digest(sorted(items))}"


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
    "last_error", "source_bom_hint", "source_analysis_hint",
    "findings_digest", "analyses_digest", "vulns_digest", "bom_digest",
    "analyses_changed_in_dt", "analyses_export_echoes", "generation",
    "staged_generation", "requested_at", "requested_by", "request_id",
    "findings_read_at", "vulns_read_at", "bom_read_at", "read_bom_signal",
    "read_analysis_signal", "staged_kinds", "staged_digests_json",
    "last_request_id", "last_request_by", "last_request_at", "last_request_state",
    "last_request_finished_at", "last_request_error", "portfolio_digest",
    "queued_reason",
)
_READ_AT = {KIND_FINDINGS: "findings_read_at", KIND_VULNS: "vulns_read_at", KIND_BOM: "bom_read_at"}
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
                        source_bom_hint = ?, source_analysis_hint = ?
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
        portfolio: Optional[str] = None,
    ) -> bool:
        """A successful read of one kind. Returns whether its content changed
        (a known digest differs); that bumps the generation, or, while the
        scheduler stages a sync of the version, is noted for its commit."""
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
            if portfolio is not None:
                # Compared by the next portfolio pass (``mark_checked``).
                assignments["portfolio_digest"] = portfolio
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
            assignments[_READ_AT[kind]] = at
            if row["staged_generation"] is not None:
                # Staged: the digests, counts and read time wait beside the
                # committed ones; only ``commit`` applies them. A sync that
                # never commits leaves the committed digests as they were,
                # so the next sync sees the change again.
                staged = json.loads(row["staged_digests_json"] or "{}")
                staged.update(assignments)
                kinds = set(filter(None, (row["staged_kinds"] or "").split(",")))
                if changed:
                    kinds.add(kind)
                connection.execute(
                    """
                    UPDATE sync_versions SET staged_digests_json = ?, staged_kinds = ?,
                        last_attempt_at = ?
                    WHERE project_uuid = ?
                    """,
                    (json.dumps(staged), ",".join(sorted(kinds)), at, project_uuid),
                )
                return changed
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
        self,
        project_uuid: str,
        error: BaseException,
        *,
        at: Optional[str] = None,
        next_due_at: Optional[str] = None,
    ) -> int:
        """A failed read. Returns the consecutive failures. A staged sync is
        left alone (a failed request-path read must not drop the scheduler's
        stage; the scheduler drops its own with ``drop_stage``), and a call
        the circuit breaker refused is not the version's failure."""
        at = at or _now()
        connection = self._connection()
        with connection:
            row = self._ensure(connection, project_uuid, at)
            if isinstance(error, SourceUnavailable):
                return int(row["consecutive_failures"] or 0)
            settled = row["status"] if row["status"] == STATUS_GONE else STATUS_FAILED
            # While staged, the transient status shows the running sync.
            status = row["status"] if row["staged_generation"] is not None else settled
            connection.execute(
                """
                UPDATE sync_versions SET status = ?, settled_status = ?,
                    last_attempt_at = ?, consecutive_failures = consecutive_failures + 1,
                    last_error_class = ?, last_error = ?,
                    next_due_at = COALESCE(?, next_due_at)
                WHERE project_uuid = ?
                """,
                (
                    status, settled, at, type(error).__name__, str(error)[:500],
                    next_due_at, project_uuid,
                ),
            )
            if row["requested_at"]:
                # The request stays (it is tried again after the backoff);
                # its outcome so far is a failure, with why.
                connection.execute(
                    """
                    UPDATE sync_versions SET last_request_id = request_id,
                        last_request_by = requested_by, last_request_at = requested_at,
                        last_request_state = 'failed', last_request_finished_at = ?,
                        last_request_error = ?
                    WHERE project_uuid = ?
                    """,
                    (at, f"{type(error).__name__}: {str(error)[:400]}", project_uuid),
                )
            return int(row["consecutive_failures"] or 0) + 1

    # -- the scheduler's transitions (ADR 0004, "Generations", "Recovery") ----

    def rows(self) -> list[dict[str, Any]]:
        """Every version with all scheduling columns, for planning."""
        rows = self._connection().execute(
            f"SELECT {', '.join(_COLUMNS)} FROM sync_versions"
        ).fetchall()
        return [dict(zip(_COLUMNS, row)) for row in rows]

    def row(self, project_uuid: str) -> Optional[dict[str, Any]]:
        row = self._row(self._connection(), project_uuid)
        if row is not None:
            row.pop("analyses_index_json", None)
        return row

    def set_status(self, project_uuid: str, status: str) -> None:
        """``queued`` or ``syncing``: transient, the settled status stays."""
        self.set_statuses([project_uuid], status)

    def queue(self, reasons: Mapping[str, str]) -> None:
        """Queue these versions, each with the reason it is due (one
        transaction): ``queued_reason`` is what the queue shows and logs."""
        if not reasons:
            return
        connection = self._connection()
        with connection:
            connection.executemany(
                "UPDATE sync_versions SET status = ?, queued_reason = ? "
                "WHERE project_uuid = ? AND status != ?",
                [(STATUS_QUEUED, reason, uuid, STATUS_GONE) for uuid, reason in reasons.items()],
            )

    def set_statuses(self, project_uuids: Iterable[str], status: str) -> None:
        """One transaction for many versions (a plan queues many at once)."""
        uuids = list(project_uuids)
        if not uuids:
            return
        connection = self._connection()
        with connection:
            connection.executemany(
                "UPDATE sync_versions SET status = ? WHERE project_uuid = ? AND status != ?",
                [(status, uuid, STATUS_GONE) for uuid in uuids],
            )

    def settle(self, project_uuids: Iterable[str]) -> None:
        """Back to the settled status: versions dropped from the queue."""
        uuids = list(project_uuids)
        if not uuids:
            return
        connection = self._connection()
        with connection:
            connection.executemany(
                "UPDATE sync_versions SET status = settled_status, queued_reason = NULL "
                "WHERE project_uuid = ? AND staged_generation IS NULL",
                [(uuid,) for uuid in uuids],
            )

    def request(
        self, project_uuids: Iterable[str], *, by: Optional[str], at: Optional[str] = None
    ) -> list[dict[str, Any]]:
        """Ask for a read of these versions before anything else (P0),
        persisted with ``requested_at``, ``requested_by`` and ``request_id``.
        A version whose request still waits keeps it: repeated clicks are one
        request, and its ``request_id`` is returned (``new`` False). A
        request made while a version syncs is kept for the next read
        (``commit`` clears only requests older than the sync). Versions not
        active or gone are left out."""
        at = at or _now()
        uuids = list(dict.fromkeys(str(uuid) for uuid in project_uuids if uuid))
        if not uuids:
            return []
        connection = self._connection()
        result: list[dict[str, Any]] = []
        with connection:
            for uuid in uuids:
                row = connection.execute(
                    "SELECT request_id, requested_at FROM sync_versions "
                    "WHERE project_uuid = ? AND active_in_dt = 1 AND status != ?",
                    (uuid, STATUS_GONE),
                ).fetchone()
                if row is None:
                    continue
                if row[1]:
                    result.append({"project_uuid": uuid, "request_id": row[0], "new": False})
                    continue
                request_id = uuid4().hex
                connection.execute(
                    "UPDATE sync_versions SET requested_at = ?, requested_by = ?, "
                    "request_id = ? WHERE project_uuid = ?",
                    (at, by, request_id, uuid),
                )
                result.append({"project_uuid": uuid, "request_id": request_id, "new": True})
        return result

    def cancel_requests(
        self, project_uuids: Optional[Iterable[str]] = None, *, at: Optional[str] = None,
        by: Optional[str] = None,
    ) -> list[str]:
        """Withdraw the waiting requests (of these versions, or all): each is
        kept as the last request with state ``cancelled``. Returns the
        versions whose request was withdrawn."""
        at = at or _now()
        connection = self._connection()
        cancelled: list[str] = []
        with connection:
            rows = connection.execute(
                "SELECT project_uuid, request_id, requested_by, requested_at "
                "FROM sync_versions WHERE requested_at IS NOT NULL"
            ).fetchall()
            wanted = None if project_uuids is None else {str(uuid) for uuid in project_uuids}
            for uuid, request_id, requested_by, requested_at in rows:
                if wanted is not None and uuid not in wanted:
                    continue
                connection.execute(
                    "UPDATE sync_versions SET requested_at = NULL, requested_by = NULL, "
                    "request_id = NULL, last_request_id = ?, last_request_by = ?, "
                    "last_request_at = ?, last_request_state = 'cancelled', "
                    "last_request_finished_at = ?, last_request_error = ? "
                    "WHERE project_uuid = ?",
                    (request_id, requested_by, requested_at, at,
                     f"Cancelled by {by}" if by else "Cancelled", uuid),
                )
                cancelled.append(uuid)
        return cancelled

    def forget_read(self, project_uuid: str, kind: str) -> None:
        """Make one kind due again: its last read time is forgotten."""
        column = _READ_AT[kind]
        connection = self._connection()
        with connection:
            connection.execute(
                f"UPDATE sync_versions SET {column} = NULL WHERE project_uuid = ?",
                (project_uuid,),
            )

    def drop_stage(self, project_uuid: str) -> None:
        """The scheduler's sync ended without a commit: its staged reads are
        forgotten and the status settles."""
        connection = self._connection()
        with connection:
            connection.execute(
                """
                UPDATE sync_versions SET status = settled_status, staged_generation = NULL,
                    staged_kinds = NULL, staged_digests_json = NULL, queued_reason = NULL
                WHERE project_uuid = ?
                """,
                (project_uuid,),
            )

    def stage(self, project_uuid: str, *, at: Optional[str] = None) -> None:
        """Start a staged sync: reads note their changes for ``commit``."""
        at = at or _now()
        connection = self._connection()
        with connection:
            row = self._ensure(connection, project_uuid, at)
            connection.execute(
                """
                UPDATE sync_versions SET status = ?, staged_generation = ?,
                    staged_kinds = '', staged_digests_json = ?, last_attempt_at = ?,
                    queued_reason = NULL
                WHERE project_uuid = ?
                """,
                (
                    STATUS_GONE if row["status"] == STATUS_GONE else STATUS_SYNCING,
                    int(row["generation"] or 0) + 1,
                    # What the list said when the sync started: what it reads.
                    json.dumps(
                        {
                            "_signals": {
                                "bom": row["source_bom_hint"],
                                "analysis": row["source_analysis_hint"],
                            },
                            "_started_at": at,
                        }
                    ),
                    at,
                    project_uuid,
                ),
            )

    def commit(
        self,
        project_uuid: str,
        *,
        at: Optional[str] = None,
        kinds_read: Iterable[str] = (KIND_FINDINGS, KIND_VULNS, KIND_BOM),
    ) -> tuple[list[str], bool, int]:
        """Commit a staged sync in one transaction: its digests apply, the
        generation moves once when a kind changed or on a first import, and
        the status settles. The list signals seen when the sync started count
        as read only for the kinds it read (BOM import: the BOM; vulnerability
        analysis: the findings), and only a request made before it started is
        answered. Returns the changed kinds, whether it was the first import,
        and the generation."""
        at = at or _now()
        kinds_read = set(kinds_read)
        connection = self._connection()
        with connection:
            row = self._ensure(connection, project_uuid, at)
            if row["staged_generation"] is None:
                # Dropped meanwhile (recovery, or a failure): nothing to commit.
                return [], False, int(row["generation"] or 0)
            staged = json.loads(row["staged_digests_json"] or "{}")
            signals = staged.pop("_signals", {})
            started_at = staged.pop("_started_at", None)
            kinds = sorted(filter(None, (row["staged_kinds"] or "").split(",")))
            first = row["last_success_at"] is None
            generation = int(row["generation"] or 0)
            if kinds or first:
                generation += 1
            status = STATUS_GONE if row["status"] == STATUS_GONE else STATUS_SYNCED
            assignments = {
                **staged,
                "status": status,
                "settled_status": status,
                "generation": generation,
                "staged_generation": None,
                "staged_kinds": None,
                "staged_digests_json": None,
                "last_success_at": at,
                "consecutive_failures": 0,
                "last_error_class": None,
                "last_error": None,
                "next_due_at": None,
            }
            if kinds or first:
                assignments["last_change_at"] = at
            if KIND_BOM in kinds_read:
                assignments["read_bom_signal"] = signals.get("bom")
            if KIND_FINDINGS in kinds_read:
                assignments["read_analysis_signal"] = signals.get("analysis")
            if row["requested_at"] and started_at and row["requested_at"] <= started_at:
                # Answered: the request is cleared, its outcome kept.
                assignments.update(
                    requested_at=None, requested_by=None, request_id=None,
                    last_request_id=row["request_id"], last_request_by=row["requested_by"],
                    last_request_at=row["requested_at"], last_request_state="done",
                    last_request_finished_at=at, last_request_error=None,
                )
            connection.execute(
                f"UPDATE sync_versions SET {', '.join(f'{name} = ?' for name in assignments)} "
                "WHERE project_uuid = ?",
                (*assignments.values(), project_uuid),
            )
        return kinds, first, generation

    def portfolio_digests(self) -> dict[str, Optional[str]]:
        """Per version, the portfolio digest of its last findings read; one
        of an older digest version counts as none."""
        prefix = f"{PORTFOLIO_DIGEST_VERSION}:"
        return {
            str(row[0]): (row[1] if row[1] and str(row[1]).startswith(prefix) else None)
            for row in self._connection().execute(
                "SELECT project_uuid, portfolio_digest FROM sync_versions"
            )
        }

    def set_portfolio_digests(self, digests: Mapping[str, str]) -> None:
        """Seed the portfolio digest of versions that have none yet (read
        before the portfolio pass existed), from their stored findings."""
        connection = self._connection()
        with connection:
            connection.executemany(
                "UPDATE sync_versions SET portfolio_digest = ? "
                "WHERE project_uuid = ? AND (portfolio_digest IS NULL "
                "OR portfolio_digest NOT LIKE ?)",
                [
                    (digest, uuid, f"{PORTFOLIO_DIGEST_VERSION}:%")
                    for uuid, digest in digests.items()
                ],
            )

    def mark_checked(
        self,
        project_uuids: Iterable[str],
        *,
        at: str,
        started_at: str,
        analysis_hints: Optional[Mapping[str, Any]] = None,
    ) -> list[str]:
        """A portfolio pass that started at ``started_at`` found these
        versions as their last findings read left them: their findings count
        as read at ``at`` (the safety re-read and the other kinds keep their
        own times), the analysis hint seen when the pass started counts as
        read (a findings read covers it), the status settles, and a request
        made before the pass started is answered. Returns the versions whose
        request it answered."""
        answered: list[str] = []
        connection = self._connection()
        with connection:
            for uuid in project_uuids:
                row = self._row(connection, uuid)
                if row is None or row["staged_generation"] is not None:
                    continue  # a sync of its own is running: it decides
                assignments: dict[str, Any] = {"findings_read_at": at}
                if analysis_hints is not None and uuid in analysis_hints:
                    assignments["read_analysis_signal"] = analysis_hints[uuid]
                if row["status"] not in (STATUS_GONE,):
                    assignments["status"] = row["settled_status"] or STATUS_SYNCED
                if row["requested_at"] and row["requested_at"] <= started_at:
                    assignments.update(
                        requested_at=None, requested_by=None, request_id=None,
                        last_request_id=row["request_id"], last_request_by=row["requested_by"],
                        last_request_at=row["requested_at"], last_request_state="done",
                        last_request_finished_at=at, last_request_error=None,
                    )
                    answered.append(uuid)
                connection.execute(
                    f"UPDATE sync_versions SET {', '.join(f'{n} = ?' for n in assignments)} "
                    "WHERE project_uuid = ?",
                    (*assignments.values(), uuid),
                )
        return answered

    def set_next_due(self, project_uuid: str, next_due_at: Optional[str]) -> None:
        """When a failed version may be tried again (its backoff)."""
        connection = self._connection()
        with connection:
            connection.execute(
                "UPDATE sync_versions SET next_due_at = ? WHERE project_uuid = ?",
                (next_due_at, project_uuid),
            )

    def recover(self) -> list[str]:
        """At startup: transient statuses return to their settled status and
        staged syncs are dropped (their committed digests are untouched, so
        a new sync sees the change again). Returns the versions whose sync
        was interrupted, to be synced again first."""
        connection = self._connection()
        with connection:
            interrupted = [
                row[0]
                for row in connection.execute(
                    "SELECT project_uuid FROM sync_versions WHERE staged_generation IS NOT NULL"
                ).fetchall()
            ]
            connection.execute(
                """
                UPDATE sync_versions SET status = settled_status,
                    staged_generation = NULL, staged_kinds = NULL, staged_digests_json = NULL
                WHERE status IN (?, ?) OR staged_generation IS NOT NULL
                """,
                (STATUS_QUEUED, STATUS_SYNCING),
            )
        return interrupted

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
            "scheduler": "source_sync",
            "versions": sum(counts.values()),
            "by_status": counts,
            "last_success_at": last_success,
            "last_change_at": last_change,
        }


def _signal(value: Any) -> Optional[str]:
    return None if value in (None, "") else str(value)


def request_progress(row: Mapping[str, Any]) -> Optional[dict[str, Any]]:
    """What became of the version's manual request: ``requested``,
    ``running``, ``done`` (with the read time), ``failed`` (with why; a
    failed request waits for the backoff and is tried again) or
    ``cancelled``."""
    if row.get("requested_at"):
        failed = (
            row.get("last_request_state") == "failed"
            and row.get("last_request_id") == row.get("request_id")
        )
        state = (
            "running" if row.get("status") == STATUS_SYNCING
            else "failed" if failed
            else "requested"
        )
        progress = {
            "id": row.get("request_id"),
            "by": row.get("requested_by"),
            "at": row.get("requested_at"),
            "state": state,
        }
        if failed:
            progress["error"] = row.get("last_request_error")
        return progress
    if row.get("last_request_id"):
        progress = {
            "id": row.get("last_request_id"),
            "by": row.get("last_request_by"),
            "at": row.get("last_request_at"),
            "state": row.get("last_request_state"),
            "finished_at": row.get("last_request_finished_at"),
        }
        if row.get("last_request_state") == "done":
            progress["read_at"] = row.get("last_request_finished_at")
        else:
            progress["error"] = row.get("last_request_error")
        return progress
    return None


def _public(row: dict[str, Any]) -> dict[str, Any]:
    row.pop("staged_digests_json", None)
    row["active_in_dt"] = bool(row["active_in_dt"])
    row["request"] = request_progress(row)
    return row
