"""What happened to the findings of a project: reported, gone, and why.

Dependency-Track reports findings; when it stops reporting one, DTVP keeps
the finding with a reason instead of letting it vanish (ADR 0003). This
module holds the rules, as functions without I/O, and the store that records
the outcome:

Every read is acted on. A read taken while the source still re-analyses a
project may lack findings it reports again later; such a finding is marked
gone and back again on the next read, its record inactive and active again
with the same value and revision, and a reason or carry-over found later
replaces the earlier one.

- ``classify_gone`` says why a finding went: its component was replaced,
  removed, or no longer matches the vulnerability.
- ``choose_carry_over`` picks the assessment a replacing finding takes over.
- ``FindingLifecycleStore`` keeps one row per finding ever reported and a
  summary of each project's last read.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import threading
from contextlib import closing
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Optional

from .assessment_outbox_services import AssessmentKey, source_matches_base
from .sqlite_migration_services import run_sqlite_migrations

logger = logging.getLogger(__name__)

FINDING_LIFECYCLE_MIGRATION_NAMESPACE = "finding_lifecycle"
PRESENCE_BACKFILL_KEY = "presence_backfilled"

STATUS_REPORTED = "reported"
STATUS_GONE = "gone"

REASON_REPLACED = "replaced"
REASON_COMPONENT_REMOVED = "component_removed"
REASON_NO_LONGER_MATCHED = "no_longer_matched"
REASON_UNDETERMINED = "undetermined"
REASON_MISSING_AT_EXPORT = "missing_at_export"

CARRY_CARRIED = "carried"
CARRY_CONFLICT = "conflict"
CARRY_OWN_ASSESSMENT = "own_assessment"
CARRY_UNDETERMINED = "undetermined"

ORIGIN_CARRIED_OVER = "carried-over"
# Carried onto the same component recreated under a new ID: unchanged, no
# review. Also the origin of the revision that takes back a review marker an
# earlier build put on such a carry (``plan_recreated_reviews``).
ORIGIN_CARRIED_OVER_RECREATED = "carried-over-recreated"
ORIGIN_CARRIED_OVER_BY_VULNERABILITY = "carried-over-by-vulnerability"

PRESENCE_COLUMNS = (
    "project_uuid",
    "component_uuid",
    "vulnerability_uuid",
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
)


def get_finding_lifecycle_migrations_path() -> Path:
    return Path(__file__).resolve().parent / "migrations" / "finding_lifecycle"


# -- pure helpers ------------------------------------------------------------


def component_identity(component: Mapping[str, Any]) -> Optional[str]:
    """What stays the same when the source recreates a component: its
    package URL without the version, else its name; lower case."""
    purl = (component.get("purl") or "").strip().lower()
    if purl:
        return re.sub(r"@[^?]+", "", purl, count=1)

    name = (component.get("name") or "").strip().lower()
    if name:
        return name

    return None


@dataclass
class BomIndex:
    """What a BOM says about its components, for classification.

    ``components`` maps each ``bom-ref`` to the component's name, version,
    package URL and identity.
    """

    refs: set[str] = field(default_factory=set)
    identities: set[str] = field(default_factory=set)
    components: dict[str, dict[str, Optional[str]]] = field(default_factory=dict)


def index_bom(bom: Any) -> Optional[BomIndex]:
    """The components of a CycloneDX BOM, nested ones included.

    Dependency-Track's ``bom-ref`` of a component is its UUID. ``None`` when
    there is no usable BOM.
    """
    if not isinstance(bom, dict):
        return None
    index = BomIndex()
    pending = list(bom.get("components") or [])
    metadata_component = (bom.get("metadata") or {}).get("component")
    if isinstance(metadata_component, dict):
        pending.append(metadata_component)
    while pending:
        component = pending.pop()
        if not isinstance(component, dict):
            continue
        ref = str(component.get("bom-ref") or "").strip()
        identity = component_identity(component)
        if ref:
            index.refs.add(ref)
            index.components[ref] = {
                "component_name": _text(component.get("name")),
                "component_version": _text(component.get("version")),
                "component_purl": _text(component.get("purl")),
                "component_identity": identity,
            }
        if identity:
            index.identities.add(identity)
        pending.extend(component.get("components") or [])
    return index


def _text(value: Any) -> Optional[str]:
    return str(value) if isinstance(value, str) and value else None


@dataclass
class ReportedFinding:
    component_uuid: str
    vulnerability_uuid: str
    vuln_id: Optional[str]
    component_name: Optional[str]
    component_version: Optional[str]
    component_purl: Optional[str]
    component_identity: Optional[str]


def reported_finding(finding: Mapping[str, Any]) -> Optional[ReportedFinding]:
    """The identity of a finding as read, or ``None`` without UUIDs."""
    component = finding.get("component") or {}
    vulnerability = finding.get("vulnerability") or {}
    if not isinstance(component, dict) or not isinstance(vulnerability, dict):
        return None
    component_uuid = str(component.get("uuid") or "").strip()
    vulnerability_uuid = str(vulnerability.get("uuid") or "").strip()
    if not component_uuid or not vulnerability_uuid:
        return None

    return ReportedFinding(
        component_uuid=component_uuid,
        vulnerability_uuid=vulnerability_uuid,
        vuln_id=_text(vulnerability.get("vulnId")),
        component_name=_text(component.get("name")),
        component_version=_text(component.get("version")),
        component_purl=_text(component.get("purl")),
        component_identity=component_identity(component),
    )


def _vuln_id_key(value: Any) -> str:
    return str(value or "").strip().upper()


class ReportedIndex:
    """The findings of one read, indexed for the rules below."""

    def __init__(self, findings: Iterable[ReportedFinding]) -> None:
        self.findings = list(findings)
        self.keys = {(f.component_uuid, f.vulnerability_uuid) for f in self.findings}
        self.components = {f.component_uuid for f in self.findings}
        self.by_vulnerability: dict[str, list[ReportedFinding]] = {}
        self.by_vuln_id: dict[str, list[ReportedFinding]] = {}
        for item in self.findings:
            self.by_vulnerability.setdefault(item.vulnerability_uuid, []).append(item)
            if item.vuln_id:
                self.by_vuln_id.setdefault(_vuln_id_key(item.vuln_id), []).append(item)

    def of_vulnerability(
        self, vulnerability_uuid: str, vuln_id: Optional[str]
    ) -> list[ReportedFinding]:
        """Reported findings of the same vulnerability: the same UUID, or the
        same identifier, in read order."""
        seen: set[tuple[str, str]] = set()
        matches: list[ReportedFinding] = []
        candidates = list(self.by_vulnerability.get(vulnerability_uuid, []))
        if vuln_id:
            candidates += self.by_vuln_id.get(_vuln_id_key(vuln_id), [])
        order = {id(item): index for index, item in enumerate(self.findings)}
        for item in sorted(candidates, key=lambda f: order[id(f)]):
            key = (item.component_uuid, item.vulnerability_uuid)
            if key not in seen:
                seen.add(key)
                matches.append(item)
        return matches


def classify_gone(
    gone_rows: Iterable[Mapping[str, Any]],
    reported: ReportedIndex,
    bom: Optional[BomIndex],
) -> dict[tuple[str, str], tuple[str, list[str]]]:
    """Why each finding went, with its successors' component UUIDs.

    - ``replaced``: the vulnerability is reported on another component of the
      same identity, and the old component has no finding left (nor, when a
      BOM is known, a place in it).
    - ``no_longer_matched``: the component, or one of the same identity, is
      still there; the vulnerability is no longer reported on it.
    - ``component_removed``: the BOM no longer has the component.
    - ``undetermined``: without a BOM the findings alone do not tell.
    """
    result: dict[tuple[str, str], tuple[str, list[str]]] = {}
    for row in gone_rows:
        component_uuid = str(row["component_uuid"])
        identity = row.get("component_identity")
        successors: list[str] = []
        if identity:
            for item in reported.of_vulnerability(
                str(row["vulnerability_uuid"]), row.get("vuln_id")
            ):
                if (
                    item.component_uuid != component_uuid
                    and item.component_identity == identity
                    and item.component_uuid not in successors
                ):
                    successors.append(item.component_uuid)
        old_reported = component_uuid in reported.components
        in_bom = bom is not None and component_uuid in bom.refs
        key = (component_uuid, str(row["vulnerability_uuid"]))
        if successors and not old_reported and not in_bom:
            result[key] = (REASON_REPLACED, successors)
        elif (
            old_reported
            or in_bom
            or (bom is not None and identity and identity in bom.identities)
        ):
            result[key] = (REASON_NO_LONGER_MATCHED, [])
        elif bom is not None:
            result[key] = (REASON_COMPONENT_REMOVED, [])
        else:
            result[key] = (REASON_UNDETERMINED, [])
    return result


def is_blank_value(value: Mapping[str, Any] | None) -> bool:
    if value is None:
        return True
    return (
        str(value.get("state") or "NOT_SET") == "NOT_SET"
        and not str(value.get("details") or "").strip()
        and not bool(value.get("suppressed"))
    )


def choose_carry_over(
    values: list[dict[str, Any]],
) -> Optional[dict[str, Any]]:
    """The value several earlier records agree on; ``None`` when they differ.

    A pending-review marker DTVP added is not a difference.
    """
    if not values:
        return None
    first = values[0]
    if all(source_matches_base(value, first) for value in values[1:]):
        return first
    return None


# -- store -------------------------------------------------------------------


class FindingLifecycleStore:
    """DTVP's record of the findings it was told about, per project.

    Lives in the same database file as the assessment records, under its
    own migration namespace. Rows are written on transitions only; a
    reported row's "last seen" is the read time in ``finding_reads``.
    """

    def __init__(self, path: str, logger: Any = None) -> None:
        self.path = path
        self.logger = logger
        self._lock = threading.RLock()
        self._initialized = False
        self._presence: dict[str, dict[tuple[str, str], dict[str, Any]]] = {}

    def _connect(self) -> sqlite3.Connection:
        directory = os.path.dirname(self.path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _ensure_initialized(self) -> None:
        with self._lock:
            if self._initialized:
                return
            with closing(self._connect()) as connection:
                run_sqlite_migrations(
                    connection,
                    namespace=FINDING_LIFECYCLE_MIGRATION_NAMESPACE,
                    migrations_path=get_finding_lifecycle_migrations_path(),
                    logger=self.logger,
                )
            self._initialized = True

    # -- backfill ----------------------------------------------------------

    def backfill_once(
        self,
        rows: Callable[[], Iterable[tuple[str, dict[str, Any], str]]],
    ) -> Optional[int]:
        """Record the findings stored before this record existed, once.

        ``rows`` yields ``(project_uuid, finding, read_at)`` for every stored
        finding. Returns the number recorded, or ``None`` when it ran before.
        """
        self._ensure_initialized()
        with self._lock, closing(self._connect()) as connection:
            if connection.execute(
                "SELECT 1 FROM finding_lifecycle_metadata WHERE key = ?",
                (PRESENCE_BACKFILL_KEY,),
            ).fetchone():
                return None
            count = 0
            with connection:
                for project_uuid, finding, read_at in rows():
                    item = reported_finding(finding)
                    if item is None:
                        continue
                    count += connection.execute(
                        f"""
                        INSERT OR IGNORE INTO finding_presence
                            ({", ".join(PRESENCE_COLUMNS)})
                        VALUES ({", ".join("?" for _ in PRESENCE_COLUMNS)})
                        """,
                        _presence_values(
                            _new_row(project_uuid, item, read_at)
                        ),
                    ).rowcount
                connection.execute(
                    """
                    INSERT INTO finding_lifecycle_metadata (key, value, updated_at)
                    VALUES (?, ?, ?)
                    """,
                    (PRESENCE_BACKFILL_KEY, str(count), datetime.now(UTC).isoformat()),
                )
            self._presence.clear()
        return count

    # -- reading -----------------------------------------------------------

    def presence(self, project_uuid: str) -> dict[tuple[str, str], dict[str, Any]]:
        """Every finding of a project ever recorded, by (component,
        vulnerability). A copy; cached until the next write."""
        self._ensure_initialized()
        with self._lock:
            cached = self._presence.get(project_uuid)
            if cached is None:
                with closing(self._connect()) as connection:
                    cached = {
                        (row["component_uuid"], row["vulnerability_uuid"]): dict(row)
                        for row in connection.execute(
                            "SELECT * FROM finding_presence WHERE project_uuid = ?",
                            (project_uuid,),
                        )
                    }
                self._presence[project_uuid] = cached
            return {key: dict(row) for key, row in cached.items()}

    def gone_row(self, key: AssessmentKey) -> Optional[dict[str, Any]]:
        """The record of a finding that is gone; ``None`` while reported or
        unknown. Cheap: answered from the per-project cache."""
        self._ensure_initialized()
        with self._lock:
            cached = self._presence.get(key[0])
            if cached is None:
                self.presence(key[0])
                cached = self._presence.get(key[0]) or {}
            row = cached.get((key[1], key[2]))
            if row is None or row.get("status") != STATUS_GONE:
                return None
            return dict(row)

    def last_read(self, project_uuid: str) -> Optional[dict[str, Any]]:
        self._ensure_initialized()
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT * FROM finding_reads WHERE project_uuid = ?",
                (project_uuid,),
            ).fetchone()
        if row is None:
            return None
        value = dict(row)
        try:
            value["went"] = json.loads(value.pop("went_json") or "{}")
        except (TypeError, ValueError):
            value["went"] = {}
        return value

    def gone_counts(self, project_uuid: str) -> dict[str, int]:
        """How many findings of the project are gone now, by reason."""
        counts: dict[str, int] = {}
        for row in self.presence(project_uuid).values():
            if row.get("status") == STATUS_GONE:
                reason = row.get("gone_reason") or REASON_UNDETERMINED
                counts[reason] = counts.get(reason, 0) + 1
        return dict(sorted(counts.items()))

    def export_gone_summary(self, project_uuid: str) -> dict[str, Any]:
        """What an export says about findings the source no longer reports.

        - ``gone``: findings gone now, by reason; a finding on a component
          the source recreated (same name and version under a new ID) is
          not counted here, it stands for an earlier generation of a
          component that is reported again;
        - ``recreated``: how many such earlier generations there are;
        - ``last_read``: the time of the last read and, by reason with
          ``recreated`` apart, the findings that went at it;
        - ``since``: when DTVP started following the version's findings.
        """
        rows = self.presence(project_uuid)
        last = self.last_read(project_uuid)
        components = _components_by_uuid(rows)
        gone: dict[str, int] = {}
        went: dict[str, int] = {}
        recreated = 0
        read_at = (last or {}).get("read_at")
        for row in rows.values():
            if row.get("status") != STATUS_GONE:
                continue
            is_recreated = _is_recreated(row, components)
            reason = row.get("gone_reason") or REASON_UNDETERMINED
            if is_recreated:
                recreated += 1
            else:
                gone[reason] = gone.get(reason, 0) + 1
            if read_at and row.get("gone_at") == read_at:
                key = "recreated" if is_recreated else reason
                went[key] = went.get(key, 0) + 1
        since = min(
            (str(row["first_seen_at"]) for row in rows.values() if row.get("first_seen_at")),
            default=None,
        )
        return {
            "gone": dict(sorted(gone.items())),
            "recreated": recreated,
            "last_read": {"at": read_at, "went": dict(sorted(went.items()))} if read_at else None,
            "since": since,
        }

    def has_data(self, project_uuid: str) -> bool:
        return bool(self.presence(project_uuid)) or self.last_read(project_uuid) is not None

    # -- writing -----------------------------------------------------------

    def record_read(
        self,
        project_uuid: str,
        rows: Iterable[dict[str, Any]],
        summary: Optional[dict[str, Any]] = None,
    ) -> None:
        """Write changed finding rows and the read's summary in one
        transaction."""
        self._ensure_initialized()
        rows = list(rows)
        with self._lock, closing(self._connect()) as connection:
            with connection:
                for row in rows:
                    connection.execute(
                        f"""
                        INSERT INTO finding_presence ({", ".join(PRESENCE_COLUMNS)})
                        VALUES ({", ".join("?" for _ in PRESENCE_COLUMNS)})
                        ON CONFLICT (project_uuid, component_uuid, vulnerability_uuid)
                        DO UPDATE SET {", ".join(
                            f"{name} = excluded.{name}"
                            for name in PRESENCE_COLUMNS[3:]
                        )},
                            -- Reported again: an acknowledgement of its
                            -- going no longer applies.
                            acknowledged_by = CASE
                                WHEN excluded.status = '{STATUS_GONE}'
                                THEN finding_presence.acknowledged_by END,
                            acknowledged_at = CASE
                                WHEN excluded.status = '{STATUS_GONE}'
                                THEN finding_presence.acknowledged_at END
                        """,
                        _presence_values({**row, "project_uuid": project_uuid}),
                    )
                if summary is not None:
                    connection.execute(
                        """
                        INSERT INTO finding_reads (
                            project_uuid, read_at, went_json, returned,
                            carried_over, not_carried
                        )
                        VALUES (?, ?, ?, ?, ?, ?)
                        ON CONFLICT (project_uuid) DO UPDATE SET
                            read_at = excluded.read_at,
                            went_json = excluded.went_json,
                            returned = excluded.returned,
                            carried_over = excluded.carried_over,
                            not_carried = excluded.not_carried
                        """,
                        (
                            project_uuid,
                            summary["read_at"],
                            json.dumps(summary.get("went") or {}, sort_keys=True),
                            int(summary.get("returned") or 0),
                            int(summary.get("carried_over") or 0),
                            int(summary.get("not_carried") or 0),
                        ),
                    )
            self._presence.pop(project_uuid, None)

    def acknowledge(
        self,
        project_uuid: str,
        findings: Iterable[tuple[str, str]],
        *,
        by: Optional[str],
        at: str,
    ) -> int:
        """Acknowledge gone findings of a project for everyone (``by`` set),
        or withdraw the acknowledgement (``by`` None). Findings that are not
        gone are left alone. Returns how many changed."""
        self._ensure_initialized()
        findings = list(dict.fromkeys(findings))
        changed = 0
        with self._lock, closing(self._connect()) as connection:
            with connection:
                for component_uuid, vulnerability_uuid in findings:
                    changed += connection.execute(
                        """
                        UPDATE finding_presence
                        SET acknowledged_by = ?, acknowledged_at = ?
                        WHERE project_uuid = ? AND component_uuid = ?
                          AND vulnerability_uuid = ? AND status = ?
                          AND acknowledged_by IS NOT ?
                        """,
                        (
                            by, at if by else None,
                            project_uuid, component_uuid, vulnerability_uuid,
                            STATUS_GONE, by,
                        ),
                    ).rowcount
            self._presence.pop(project_uuid, None)
        return changed

    def fill_components(
        self,
        project_uuid: str,
        components: Mapping[str, Mapping[str, Optional[str]]],
    ) -> int:
        """Record what became known of components a project's rows lack:
        name, version, package URL and identity. Only rows without a name
        are filled. Returns how many rows changed."""
        self._ensure_initialized()
        changed = 0
        with self._lock, closing(self._connect()) as connection:
            with connection:
                for component_uuid, fields in components.items():
                    if not fields.get("component_name"):
                        continue
                    changed += connection.execute(
                        """
                        UPDATE finding_presence
                        SET component_name = ?, component_version = ?,
                            component_purl = ?, component_identity = ?
                        WHERE project_uuid = ? AND component_uuid = ?
                          AND component_name IS NULL
                        """,
                        (
                            fields.get("component_name"),
                            fields.get("component_version"),
                            fields.get("component_purl"),
                            fields.get("component_identity"),
                            project_uuid,
                            component_uuid,
                        ),
                    ).rowcount
            self._presence.pop(project_uuid, None)
        return changed

    def mark_gone(self, key: AssessmentKey, *, reason: str, at: str) -> bool:
        """Record that a reported finding is gone, found out other than by a
        read (an export the source rejected). Unknown or already gone
        findings are left alone."""
        self._ensure_initialized()
        with self._lock, closing(self._connect()) as connection:
            with connection:
                last = connection.execute(
                    "SELECT read_at FROM finding_reads "
                    "WHERE project_uuid = ?",
                    (key[0],),
                ).fetchone()
                changed = connection.execute(
                    """
                    UPDATE finding_presence
                    SET status = ?, gone_reason = ?, gone_at = ?,
                        last_seen_at = ?, successor_component_uuid = NULL,
                        carry_over = NULL
                    WHERE project_uuid = ? AND component_uuid = ?
                      AND vulnerability_uuid = ? AND status = ?
                    """,
                    (
                        STATUS_GONE, reason, at,
                        last[0] if last is not None else None,
                        *key, STATUS_REPORTED,
                    ),
                ).rowcount
            self._presence.pop(key[0], None)
        return bool(changed)


def _new_row(project_uuid: str, item: ReportedFinding, at: str) -> dict[str, Any]:
    return {
        "project_uuid": project_uuid,
        "component_uuid": item.component_uuid,
        "vulnerability_uuid": item.vulnerability_uuid,
        "vuln_id": item.vuln_id,
        "component_name": item.component_name,
        "component_version": item.component_version,
        "component_purl": item.component_purl,
        "component_identity": item.component_identity,
        "first_seen_at": at,
        "status": STATUS_REPORTED,
        "gone_at": None,
        "last_seen_at": None,
        "gone_reason": None,
        "successor_component_uuid": None,
        "carry_over": None,
        "returned_at": None,
    }


def _presence_values(row: Mapping[str, Any]) -> tuple[Any, ...]:
    return tuple(row.get(name) for name in PRESENCE_COLUMNS)


# -- one read ----------------------------------------------------------------


@dataclass
class PresencePlan:
    """The rows a read changes, and what it counted."""

    rows: dict[tuple[str, str], dict[str, Any]]
    changed: set[tuple[str, str]] = field(default_factory=set)
    returned: int = 0
    went: dict[str, int] = field(default_factory=dict)
    newly_gone: list[tuple[str, str]] = field(default_factory=list)

    def update(self, key: tuple[str, str], **values: Any) -> None:
        row = self.rows[key]
        if any(row.get(name) != value for name, value in values.items()):
            row.update(values)
            self.changed.add(key)


def plan_reported(
    project_uuid: str,
    presence: dict[tuple[str, str], dict[str, Any]],
    reported: ReportedIndex,
    read_at: str,
) -> PresencePlan:
    """Rows for the findings just read: new ones, returning ones, and ones
    whose component details changed."""
    plan = PresencePlan(rows=presence)
    for item in reported.findings:
        key = (item.component_uuid, item.vulnerability_uuid)
        row = presence.get(key)
        if row is None:
            presence[key] = _new_row(project_uuid, item, read_at)
            plan.changed.add(key)
            continue
        if row.get("status") == STATUS_GONE:
            # Back again. What is known about when and why it went stays.
            plan.update(key, status=STATUS_REPORTED, returned_at=read_at)
            plan.returned += 1
        plan.update(
            key,
            vuln_id=item.vuln_id or row.get("vuln_id"),
            component_name=item.component_name,
            component_version=item.component_version,
            component_purl=item.component_purl,
            component_identity=item.component_identity,
        )
    return plan


def plan_gone(
    plan: PresencePlan,
    project_uuid: str,
    reported: ReportedIndex,
    records: Mapping[AssessmentKey, Mapping[str, Any]],
    *,
    read_at: str,
    last_seen_at: Optional[str],
    bom: Callable[[], Optional[BomIndex]],
) -> None:
    """Mark what a read no longer has as gone, with a reason, and
    look again at the reasons of what went before.

    ``bom`` is called when the findings alone do not decide, and to confirm
    a replacement: ``replaced`` needs a BOM without the old component.
    Without a BOM such a finding is ``undetermined``.
    """
    rows = plan.rows
    # Records of findings that went before this record existed are not
    # treated as just gone: only those still followed.
    for key, state in records.items():
        finding = (key[1], key[2])
        if (
            finding in reported.keys
            or finding in rows
            or state.get("sync_status") not in ("synced", "pending", "error", "cancelled")
        ):
            continue
        rows[finding] = {
            "project_uuid": project_uuid,
            "component_uuid": key[1],
            "vulnerability_uuid": key[2],
            "vuln_id": None,
            "component_name": None,
            "component_version": None,
            "component_purl": None,
            "component_identity": None,
            "first_seen_at": str(state.get("updated_at") or read_at),
            "status": STATUS_REPORTED,
            "gone_at": None,
            "last_seen_at": None,
            "gone_reason": None,
            "successor_component_uuid": None,
            "carry_over": None,
            "returned_at": None,
        }
        plan.changed.add(finding)

    newly = [
        key for key, row in rows.items()
        if row.get("status") == STATUS_REPORTED and key not in reported.keys
    ]
    earlier = [
        key for key, row in rows.items()
        if row.get("status") == STATUS_GONE
        and row.get("gone_reason") != REASON_REPLACED
        and key not in reported.keys
    ]
    wanted = newly + earlier
    if not wanted:
        return
    reasons = classify_gone((rows[key] for key in wanted), reported, None)
    # The findings alone suggest "replaced", but only the BOM says that the
    # old component is gone: a component still in it was not replaced, even
    # when it has no finding left and another version of it has.
    unconfirmed = [
        key for key in wanted
        if reasons[key][0] == REASON_REPLACED
        or (
            reasons[key][0] == REASON_UNDETERMINED
            and (key in newly or rows[key].get("gone_reason") == REASON_UNDETERMINED)
        )
    ]
    if unconfirmed:
        index = bom()
        if index is not None:
            reasons.update(
                classify_gone((rows[key] for key in unconfirmed), reported, index)
            )
        else:
            for key in unconfirmed:
                if reasons[key][0] == REASON_REPLACED:
                    reasons[key] = (REASON_UNDETERMINED, [])

    for key in newly:
        reason, successors = reasons[key]
        plan.update(
            key,
            status=STATUS_GONE,
            gone_at=read_at,
            last_seen_at=last_seen_at,
            gone_reason=reason,
            successor_component_uuid=successors[0] if successors else None,
            carry_over=None,
        )
        plan.went[reason] = plan.went.get(reason, 0) + 1
        plan.newly_gone.append(key)
    for key in earlier:
        reason, successors = reasons[key]
        previous = rows[key].get("gone_reason")
        # A successor found later explains the earlier loss; a reason that
        # could not be told before is replaced once it can. Otherwise the
        # first reason stays: it says why the finding went.
        if reason == REASON_REPLACED or (
            previous == REASON_UNDETERMINED and reason != REASON_UNDETERMINED
        ):
            plan.update(
                key,
                gone_reason=reason,
                successor_component_uuid=successors[0] if successors else None,
            )


@dataclass
class CarryOver:
    target: AssessmentKey
    value: dict[str, Any]
    candidates: list[AssessmentKey]
    origin: str
    # What is known of a candidate's component that its finding row lacks
    # (name, version, package URL, identity), by candidate.
    components: dict[AssessmentKey, dict[str, Optional[str]]] = field(
        default_factory=dict
    )
    # Every candidate had the target's component name, version and package
    # URL: the source recreated the same component under a new ID (a BOM
    # uploaded again). The assessment carries over unchanged, without review.
    recreated: bool = False


@dataclass
class CarryPlan:
    carries: list[CarryOver] = field(default_factory=list)
    conflicts: list[tuple[AssessmentKey, list[AssessmentKey]]] = field(
        default_factory=list
    )
    # Records that might belong to the target, but whose component is not
    # known well enough to tell: a person decides.
    undetermined: list[tuple[AssessmentKey, list[AssessmentKey]]] = field(
        default_factory=list
    )

    @property
    def not_carried(self) -> int:
        return len(self.conflicts) + len(self.undetermined)


CARRY_FROM_STATUSES = ("inactive", "pending", "error", "synced")


def _record_value(state: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "state": str(state.get("analysisState") or "NOT_SET"),
        "details": str(state.get("analysisDetails") or ""),
        "suppressed": bool(state.get("isSuppressed")),
    }


def _same_name(left: Optional[str], right: Optional[str]) -> bool:
    return bool(left and right) and left.strip().lower() == right.strip().lower()


def same_component_version(
    row: Mapping[str, Any], target: "ReportedFinding"
) -> bool:
    """The gone finding's component is the target's: same name and version,
    and the same package URL where both have one."""
    if not _same_name(row.get("component_name"), target.component_name):
        return False
    version = str(row.get("component_version") or "").strip()
    if not version or version != str(target.component_version or "").strip():
        return False
    purl = str(row.get("component_purl") or "").strip().lower()
    target_purl = str(target.component_purl or "").strip().lower()
    return not (purl and target_purl and purl != target_purl)


def plan_carry_over(
    project_uuid: str,
    targets: list[ReportedFinding],
    reported: ReportedIndex,
    records: Mapping[AssessmentKey, Mapping[str, Any]],
    rows: Mapping[tuple[str, str], Mapping[str, Any]],
    *,
    unrecorded_per_vulnerability: Mapping[str, int],
    bom: Callable[[], Optional[BomIndex]],
    previous_bom: Callable[[], Optional[BomIndex]] = lambda: None,
) -> CarryPlan:
    """Which assessments the findings in ``targets`` take over from records
    of findings that are gone.

    A candidate is a record of the same vulnerability (UUID or identifier)
    whose component is not reported any more, with a value, not cancelled or
    superseded. It counts when its finding was ``replaced``: it had the same
    component identity as the target and the BOM no longer has its
    component. A finding that is no longer matched keeps its record.

    A record from before identities were recorded counts by vulnerability,
    when it is the only reading: the target is the one finding of the
    vulnerability without a record, the BOM no longer has the record's
    component, and that component had the target's name. The name comes
    from the finding row or from the BOM DTVP stored before this read
    (``previous_bom``). When it cannot be told, nothing is carried and the
    case is ``undetermined``.
    """
    plan = CarryPlan()
    by_vulnerability: dict[str, list[AssessmentKey]] = {}
    by_vuln_id: dict[str, list[AssessmentKey]] = {}
    for key, state in records.items():
        if key[0] != project_uuid or key[1] in reported.components:
            continue
        if state.get("sync_status") not in CARRY_FROM_STATUSES:
            continue
        if is_blank_value(_record_value(state)):
            continue
        by_vulnerability.setdefault(key[2], []).append(key)
        vuln_id = (rows.get((key[1], key[2])) or {}).get("vuln_id")
        if vuln_id:
            by_vuln_id.setdefault(_vuln_id_key(vuln_id), []).append(key)

    def row_of(key: AssessmentKey) -> Mapping[str, Any]:
        return rows.get((key[1], key[2])) or {}

    for target in targets:
        target_key = (project_uuid, target.component_uuid, target.vulnerability_uuid)
        found = list(by_vulnerability.get(target.vulnerability_uuid, []))
        if target.vuln_id:
            found += [
                key for key in by_vuln_id.get(_vuln_id_key(target.vuln_id), [])
                if key not in found
            ]
        found.sort()
        candidates = [
            key for key in found
            if target.component_identity
            and row_of(key).get("component_identity") == target.component_identity
            and row_of(key).get("status") == STATUS_GONE
            and row_of(key).get("gone_reason") == REASON_REPLACED
        ]
        if candidates:
            value = choose_carry_over(
                [_record_value(records[key]) for key in candidates]
            )
            recreated = all(
                same_component_version(row_of(key), target) for key in candidates
            )
            if value is None:
                plan.conflicts.append((target_key, candidates))
            else:
                plan.carries.append(
                    CarryOver(
                        target_key,
                        value,
                        candidates,
                        ORIGIN_CARRIED_OVER_RECREATED if recreated else ORIGIN_CARRIED_OVER,
                        recreated=recreated,
                    )
                )
            continue

        unknown = [
            key for key in found
            if key[2] == target.vulnerability_uuid
            and not row_of(key).get("component_identity")
        ]
        if (
            not unknown
            or unrecorded_per_vulnerability.get(target.vulnerability_uuid) != 1
        ):
            continue
        index = bom()
        if index is None:
            continue
        absent = [key for key in unknown if key[1] not in index.refs]
        if not absent:
            continue
        components: dict[AssessmentKey, dict[str, Optional[str]]] = {}
        unnamed: list[AssessmentKey] = []
        for key in absent:
            if row_of(key).get("component_name"):
                components[key] = {}
                continue
            earlier = previous_bom()
            known = (earlier.components.get(key[1]) if earlier else None) or {}
            if known.get("component_name"):
                components[key] = dict(known)
            else:
                unnamed.append(key)
        matching = [
            key for key in components
            if _same_name(
                row_of(key).get("component_name")
                or components[key].get("component_name"),
                target.component_name,
            )
        ]
        if unnamed:
            plan.undetermined.append((target_key, sorted(matching + unnamed)))
            continue
        if not matching:
            continue
        value = choose_carry_over([_record_value(records[key]) for key in matching])
        if value is None:
            plan.conflicts.append((target_key, matching))
            continue
        plan.carries.append(
            CarryOver(
                target_key,
                value,
                matching,
                ORIGIN_CARRIED_OVER_BY_VULNERABILITY,
                {key: components[key] for key in matching if components[key]},
            )
        )
    return plan


# -- the import step ---------------------------------------------------------


@dataclass
class FindingsImport:
    """The outcome of one import of a project's findings."""

    findings: Any
    read_at: str
    went: dict[str, int] = field(default_factory=dict)
    returned: int = 0
    carried_over: list[AssessmentKey] = field(default_factory=list)
    not_carried: int = 0


@dataclass
class FollowPlan:
    """What following one read changes, before the carried-over
    assessments are saved."""

    project_uuid: str
    read_at: str
    reported: ReportedIndex
    presence: PresencePlan
    last_read: dict[str, Any]
    retired: list[AssessmentKey] = field(default_factory=list)
    carry: CarryPlan = field(default_factory=CarryPlan)
    records: dict[AssessmentKey, dict[str, Any]] = field(default_factory=dict)
    carried: list[CarryOver] = field(default_factory=list)


def follow_findings_plan(
    *,
    project_uuid: str,
    findings: list[Any],
    has_source_value: Callable[[AssessmentKey], bool],
    started_at: datetime,
    lifecycle: FindingLifecycleStore,
    outbox: Any,
    bom: Callable[[], Optional[BomIndex]],
    previous_bom: Callable[[], Optional[BomIndex]] = lambda: None,
) -> FollowPlan:
    """Follow one read of a project's findings.

    Every read records the findings it has, marks what it lacks as gone,
    retires their records and plans the carry-over to replacing findings.
    A read taken while the source still re-analyses the project is acted on
    as well: what it lacked returns, or is explained, on a later read.
    ``has_source_value`` says whether the source holds an assessment for a
    finding. ``bom`` reads the project's BOM now; ``previous_bom`` is the
    BOM DTVP stored before. Blocking: run it in a worker thread.
    """
    read_at = started_at.astimezone(UTC).isoformat()
    reported = ReportedIndex(
        item
        for finding in findings
        if isinstance(finding, dict) and (item := reported_finding(finding))
    )
    last = lifecycle.last_read(project_uuid) or {}
    presence = plan_reported(
        project_uuid, lifecycle.presence(project_uuid), reported, read_at
    )
    plan = FollowPlan(project_uuid, read_at, reported, presence, last)

    records = outbox.project_states(project_uuid)
    plan_gone(
        presence,
        project_uuid,
        reported,
        records,
        read_at=read_at,
        last_seen_at=last.get("read_at"),
        bom=bom,
    )
    gone = {
        (project_uuid, *key): row.get("gone_reason") or REASON_UNDETERMINED
        for key, row in presence.rows.items()
        if row.get("status") == STATUS_GONE and key not in reported.keys
    }
    plan.retired = outbox.retire_missing(project_uuid, gone, fetched_at=started_at)
    plan.records = records = outbox.project_states(project_uuid)

    targets: list[ReportedFinding] = []
    unrecorded: dict[str, int] = {}
    for item in reported.findings:
        key = (project_uuid, item.component_uuid, item.vulnerability_uuid)
        if key in records:
            continue
        unrecorded[item.vulnerability_uuid] = unrecorded.get(item.vulnerability_uuid, 0) + 1
        if not has_source_value(key):
            targets.append(item)
    plan.carry = plan_carry_over(
        project_uuid,
        targets,
        reported,
        records,
        presence.rows,
        unrecorded_per_vulnerability=unrecorded,
        bom=bom,
        previous_bom=previous_bom,
    )
    return plan


def record_carry_over(
    plan: FollowPlan,
    carried: list[CarryOver],
    *,
    has_source_value: Callable[[AssessmentKey], bool],
) -> None:
    """Note on the gone findings what became of their assessments."""
    plan.carried = list(carried)
    rows = plan.presence.rows

    def ensure_row(
        candidate: AssessmentKey,
        successor: Optional[str],
        component: Mapping[str, Optional[str]],
    ) -> tuple[str, str]:
        finding = (candidate[1], candidate[2])
        if finding not in rows:
            # Gone before DTVP recorded findings: only the record is known,
            # and what the stored BOM said of its component. The BOM no
            # longer has the component: the carry-over rules ask for that.
            state = plan.records.get(candidate) or {}
            target = next(
                (
                    item for item in plan.reported.of_vulnerability(candidate[2], None)
                    if item.component_uuid == successor
                ),
                None,
            ) or next(iter(plan.reported.of_vulnerability(candidate[2], None)), None)
            at = str(state.get("updated_at") or plan.read_at)
            rows[finding] = {
                "project_uuid": plan.project_uuid,
                "component_uuid": finding[0],
                "vulnerability_uuid": finding[1],
                "vuln_id": target.vuln_id if target else None,
                "component_name": None,
                "component_version": None,
                "component_purl": None,
                "component_identity": None,
                "first_seen_at": at,
                "status": STATUS_GONE,
                "gone_at": at,
                "last_seen_at": None,
                "gone_reason": REASON_COMPONENT_REMOVED,
                "successor_component_uuid": None,
                "carry_over": None,
                "returned_at": None,
            }
            plan.presence.changed.add(finding)
        if component and not rows[finding].get("component_name"):
            plan.presence.update(
                finding,
                **{
                    name: component.get(name)
                    for name in (
                        "component_name",
                        "component_version",
                        "component_purl",
                        "component_identity",
                    )
                },
            )
        return finding

    done: set[tuple[str, str]] = set()
    for carry in carried:
        for candidate in carry.candidates:
            finding = (candidate[1], candidate[2])
            if finding in done:
                continue
            done.add(finding)
            ensure_row(candidate, carry.target[1], carry.components.get(candidate) or {})
            plan.presence.update(
                finding,
                gone_reason=REASON_REPLACED,
                successor_component_uuid=carry.target[1],
                carry_over=CARRY_CARRIED,
            )

    for outcome, label, cases in (
        (CARRY_CONFLICT, "differ", plan.carry.conflicts),
        (CARRY_UNDETERMINED, "may belong to it, component unknown", plan.carry.undetermined),
    ):
        for target, candidates in cases:
            changed = False
            for candidate in candidates:
                finding = ensure_row(candidate, None, {})
                if rows[finding].get("carry_over") != outcome:
                    plan.presence.update(finding, carry_over=outcome)
                    changed = True
            if changed:
                logger.info(
                    "Assessments of %d gone finding(s) %s; not carried over "
                    "to %s/%s in %s",
                    len(candidates), label, target[1], target[2], plan.project_uuid,
                )

    # The replacing finding has an assessment of its own: nothing to carry.
    for finding, row in rows.items():
        if (
            row.get("status") != STATUS_GONE
            or row.get("gone_reason") != REASON_REPLACED
            or row.get("carry_over") is not None
            or not row.get("successor_component_uuid")
        ):
            continue
        record = plan.records.get((plan.project_uuid, *finding))
        if record is None or is_blank_value(_record_value(record)):
            continue
        successors = [
            item for item in plan.reported.of_vulnerability(
                finding[1], row.get("vuln_id")
            )
            if item.component_uuid == row["successor_component_uuid"]
        ]
        if any(
            (plan.project_uuid, item.component_uuid, item.vulnerability_uuid)
            in plan.records
            or has_source_value(
                (plan.project_uuid, item.component_uuid, item.vulnerability_uuid)
            )
            for item in successors
        ):
            plan.presence.update(finding, carry_over=CARRY_OWN_ASSESSMENT)


_REVIEW_MARKER_SUFFIX = "\n\n[Status: Pending Review]"


def plan_recreated_reviews(
    project_uuid: str,
    rows: Mapping[tuple[str, str], Mapping[str, Any]],
    records: Mapping[AssessmentKey, Mapping[str, Any]],
    reported: "ReportedIndex",
    carried_last: set[AssessmentKey],
) -> list[tuple[AssessmentKey, dict[str, Any], int]]:
    """Carries onto a recreated component that an earlier build marked for
    review: the value to take back without the marker, and the revision it
    is written on top of.

    ``carried_last`` are the records whose latest revision is a carry-over
    (nobody saved since). One counts when every gone finding it was carried
    from had the target's name, version and package URL, none of their
    values was pending review, and the record still holds exactly that value
    with the marker the carry added.
    """
    by_target: dict[AssessmentKey, list[AssessmentKey]] = {}
    for finding, row in rows.items():
        if row.get("status") != STATUS_GONE or row.get("carry_over") != CARRY_CARRIED:
            continue
        successor = row.get("successor_component_uuid")
        if successor:
            by_target.setdefault(
                (project_uuid, str(successor), finding[1]), []
            ).append((project_uuid, *finding))
    result = []
    for key in sorted(carried_last):
        record = records.get(key)
        candidates = by_target.get(key)
        if record is None or not candidates:
            continue
        if record.get("sync_status") not in CARRY_FROM_STATUSES:
            continue
        target = next(
            (item for item in reported.of_vulnerability(key[2], None)
             if item.component_uuid == key[1]),
            None,
        )
        current = _record_value(record)
        if target is None or not current["details"].endswith(_REVIEW_MARKER_SUFFIX):
            continue
        olds = [records.get(candidate) for candidate in candidates]
        if any(old is None for old in olds):
            continue
        values = [_record_value(old) for old in olds]
        before = {
            **current,
            "details": current["details"][: -len(_REVIEW_MARKER_SUFFIX)],
        }
        if all(
            same_component_version(rows[(candidate[1], candidate[2])], target)
            and "[Status: Pending Review]" not in value["details"]
            and value == before
            for candidate, value in zip(candidates, values)
        ):
            result.append((key, before, int(record.get("revision") or 0)))
    return result


def own_assessments_to_supersede(
    project_uuid: str,
    rows: Mapping[tuple[str, str], Mapping[str, Any]],
    records: Mapping[AssessmentKey, Mapping[str, Any]],
) -> list[AssessmentKey]:
    """Records of gone findings whose successor has an approved assessment
    of its own. They stop being carry candidates (``superseded``); left
    ``inactive``, the next recreation would carry them again or report a
    conflict with the successor's value."""
    result = []
    for finding, row in rows.items():
        if (
            row.get("status") != STATUS_GONE
            or row.get("carry_over") != CARRY_OWN_ASSESSMENT
            or not row.get("successor_component_uuid")
        ):
            continue
        old_key = (project_uuid, *finding)
        old = records.get(old_key)
        if old is None or old.get("sync_status") not in CARRY_FROM_STATUSES:
            continue
        own = records.get((project_uuid, str(row["successor_component_uuid"]), finding[1]))
        if own is None or own.get("sync_status") not in ("synced", "pending", "error"):
            continue
        value = _record_value(own)
        if is_blank_value(value) or "[Status: Pending Review]" in value["details"]:
            continue
        result.append(old_key)
    return result


def read_summary(plan: FollowPlan) -> dict[str, Any]:
    return {
        "read_at": plan.read_at,
        "went": dict(sorted(plan.presence.went.items())),
        "returned": plan.presence.returned,
        "carried_over": len(plan.carried),
        "not_carried": plan.carry.not_carried,
    }


def _components_by_uuid(
    rows: Mapping[tuple[str, str], Mapping[str, Any]],
) -> dict[str, Mapping[str, Any]]:
    """A finding row per component, a reported one where there is one."""
    components: dict[str, Mapping[str, Any]] = {}
    for row in rows.values():
        if row.get("status") == STATUS_REPORTED or row["component_uuid"] not in components:
            components[row["component_uuid"]] = row
    return components


def _is_recreated(
    row: Mapping[str, Any], components: Mapping[str, Mapping[str, Any]]
) -> bool:
    """The gone finding's successor is the same component (name and version)
    under a new ID: the source recreated it, nothing was replaced."""
    successor_uuid = row.get("successor_component_uuid")
    successor = components.get(successor_uuid) if successor_uuid else None
    version = str(row.get("component_version") or "").strip()
    return bool(
        row.get("gone_reason") == REASON_REPLACED
        and successor is not None
        and _same_name(row.get("component_name"), successor.get("component_name"))
        and version
        and version == str(successor.get("component_version") or "").strip()
    )


def describe_gone_findings(
    lifecycle: FindingLifecycleStore,
    outbox: Any,
    project_uuid: str,
) -> Optional[dict[str, Any]]:
    """The gone findings of a project version with the last read, for
    display. ``None`` when DTVP has no record of the version's findings."""
    rows = lifecycle.presence(project_uuid)
    last = lifecycle.last_read(project_uuid)
    if not rows and last is None:
        return None
    components = _components_by_uuid(rows)
    findings = []
    for row in rows.values():
        if row.get("status") != STATUS_GONE:
            continue
        successor_uuid = row.get("successor_component_uuid")
        successor = components.get(successor_uuid) if successor_uuid else None
        record = outbox.get_overlay(
            (project_uuid, row["component_uuid"], row["vulnerability_uuid"])
        )
        recreated = _is_recreated(row, components)
        acknowledged = row.get("acknowledged_by")
        findings.append(
            {
                "component_uuid": row["component_uuid"],
                "component_name": row.get("component_name"),
                "component_version": row.get("component_version"),
                "component_purl": row.get("component_purl"),
                "vulnerability_uuid": row["vulnerability_uuid"],
                "vuln_id": row.get("vuln_id"),
                "reason": row.get("gone_reason") or REASON_UNDETERMINED,
                "recreated": recreated,
                "gone_at": row.get("gone_at"),
                "last_seen_at": row.get("last_seen_at"),
                "carry_over": row.get("carry_over"),
                "successor": (
                    {
                        "component_uuid": successor_uuid,
                        "component_name": (successor or {}).get("component_name"),
                        "component_version": (successor or {}).get("component_version"),
                    }
                    if successor_uuid
                    else None
                ),
                "assessment": (
                    {
                        "sync_status": record.get("sync_status"),
                        "state": record.get("analysisState"),
                        "revision": int(record.get("revision") or 0),
                    }
                    if record is not None
                    else None
                ),
                "acknowledged_by": acknowledged,
                "acknowledged_at": row.get("acknowledged_at") if acknowledged else None,
                "needs_attention": not acknowledged
                and needs_attention(row, record),
            }
        )
    findings.sort(
        key=lambda item: (
            str(item["gone_at"] or ""),
            str(item["vuln_id"] or ""),
            str(item["component_name"] or ""),
        ),
        reverse=True,
    )
    return {
        "project_uuid": project_uuid,
        "last_read": (
            {
                "read_at": last["read_at"],
                "went": last.get("went") or {},
                "returned": int(last.get("returned") or 0),
                "carried_over": int(last.get("carried_over") or 0),
                "not_carried": int(last.get("not_carried") or 0),
            }
            if last is not None
            else None
        ),
        "gone": lifecycle.gone_counts(project_uuid),
        "summary": summarize_gone(findings),
        "trend": gone_trend(rows.values()),
        "findings": findings,
    }


# Carry-over outcomes that leave an assessment behind with nobody to apply
# it: a person has to decide.
ATTENTION_CARRY_OVER = (CARRY_CONFLICT, CARRY_UNDETERMINED)


def needs_attention(
    row: Mapping[str, Any], record: Optional[Mapping[str, Any]]
) -> bool:
    """A gone finding whose assessment did not carry over and still holds a
    value: nobody else will apply it."""
    if row.get("status") != STATUS_GONE or row.get("carry_over") not in ATTENTION_CARRY_OVER:
        return False
    if record is None or record.get("sync_status") in ("superseded", "cancelled"):
        return False
    return not is_blank_value(_record_value(record))


def summarize_gone(findings: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Counts of the described gone findings: by reason (with components the
    source recreated apart from real replacements), by carry-over outcome,
    and what needs attention or was acknowledged."""
    by_reason: dict[str, int] = {}
    by_carry_over: dict[str, int] = {}
    attention = acknowledged = 0
    for finding in findings:
        reason = "recreated" if finding.get("recreated") else str(finding.get("reason"))
        by_reason[reason] = by_reason.get(reason, 0) + 1
        carry = finding.get("carry_over") or (
            "no_assessment" if finding.get("assessment") is None else "kept"
        )
        by_carry_over[carry] = by_carry_over.get(carry, 0) + 1
        attention += bool(finding.get("needs_attention"))
        acknowledged += bool(finding.get("acknowledged_by"))
    return {
        "by_reason": dict(sorted(by_reason.items())),
        "by_carry_over": dict(sorted(by_carry_over.items())),
        "needs_attention": attention,
        "acknowledged": acknowledged,
    }


def gone_trend(rows: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """How many findings went per day, by reason, from the time each went.
    A finding that came back since still counts on the day it went; one that
    went twice counts on its latest day only (the time it went is kept per
    finding, not per occurrence)."""
    days: dict[str, dict[str, int]] = {}
    for row in rows:
        gone_at = str(row.get("gone_at") or "")
        if len(gone_at) < 10:
            continue
        reason = row.get("gone_reason") or REASON_UNDETERMINED
        counts = days.setdefault(gone_at[:10], {})
        counts[reason] = counts.get(reason, 0) + 1
    return [
        {"day": day, "went": dict(sorted(counts.items()))}
        for day, counts in sorted(days.items())
    ]
