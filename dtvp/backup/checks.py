"""Referential (R1-R6) and semantic (W1-W8) checks over the records of a
dump. Records are fed in the fixed entity order; export, verify and restore
share this checker. Key sets are held in memory, which grows with the
number of assessments."""

from collections import defaultdict
from typing import Any, Iterable

from .entities import ENTITIES
from .errors import Finding

_RAW_FIELDS = ("payload_raw", "target_raw")
_LIST_ITEMS = {
    "source_project": "projects",
    "source_finding": "findings",
    "source_project_vulnerability": "project_vulnerabilities",
}


def _key(record: dict[str, Any]) -> tuple[str, str, str]:
    key = record["key"]
    return (key["project_uuid"], key["component_uuid"], key["vulnerability_uuid"])


class RecordChecker:
    def __init__(self) -> None:
        self.errors: list[Finding] = []
        self.warnings: list[Finding] = []
        self._seen: dict[str, set[Any]] = defaultdict(set)
        self._assessments: dict[tuple[str, str, str], tuple[int, str, str | None]] = {}
        self._max_history: dict[tuple[str, str, str], int] = {}
        self._outbox: dict[tuple[str, str, str], str] = {}
        self._update_ids: set[str] = set()
        self._token_hashes: set[str] = set()
        self._results: set[str] = set()
        self._evidence: set[str] = set()
        self.has_evidence_material = False
        self._snapshots: dict[tuple[str, str], tuple[str, int]] = {}
        self._items: dict[tuple[str, str], int] = defaultdict(int)
        self._max_ids = {"revision": 0, "token_audit": 0}
        self.raw_counts: dict[str, int] = defaultdict(int)

    def _error(self, code: str, message: str) -> None:
        self.errors.append(Finding(code, message))

    def _warn(self, code: str, message: str) -> None:
        self.warnings.append(Finding(code, message))

    def add(self, entity: str, record: dict[str, Any]) -> None:
        natural = ENTITIES[entity].natural_key(record)
        seen = self._seen[entity]
        if natural in seen:
            self._error("R1", f"Duplicate {entity} {natural!r}")
        seen.add(natural)
        if any(field in record for field in _RAW_FIELDS):
            self.raw_counts[entity] += 1

        if entity == "assessment":
            sync = record["sync"]
            self._assessments[natural] = (
                record["revision"],
                sync["status"],
                sync["update_id"],
            )
        elif entity == "revision":
            key = _key(record)
            self._max_ids["revision"] = max(self._max_ids["revision"], record["revision_id"])
            if key not in self._assessments:
                self._error(
                    "R3",
                    f"History entry {record['revision_id']} belongs to no assessment {key!r}",
                )
            self._max_history[key] = max(self._max_history.get(key, -1), record["revision"])
        elif entity == "outbox_entry":
            update_id = record["update_id"]
            if update_id in self._update_ids:
                self._error("R2", f"Duplicate outbox update_id {update_id!r}")
            self._update_ids.add(update_id)
            self._outbox[natural] = update_id
            assessment = self._assessments.get(natural)
            if assessment is None:
                self._warn("W5", f"Outbox entry {update_id} for {natural!r} has no assessment")
            else:
                if assessment[1] not in ("pending", "error"):
                    self._warn(
                        "W3",
                        f"Outbox entry {update_id} for an assessment that is {assessment[1]}",
                    )
                if assessment[2] != update_id:
                    self._warn(
                        "W1",
                        f"Outbox entry {update_id} differs from the assessment's update_id "
                        f"{assessment[2]!r}",
                    )
        elif entity == "access_token":
            if record["token_hash"] in self._token_hashes:
                self._error("R2", f"Duplicate token digest of token {record['token_id']!r}")
            self._token_hashes.add(record["token_hash"])
        elif entity == "token_audit":
            self._max_ids["token_audit"] = max(self._max_ids["token_audit"], record["audit_id"])
        elif entity == "code_analysis_result":
            self._results.add(record["analysis_run_id"])
        elif entity == "code_analysis_application":
            if record["analysis_run_id"] not in self._results:
                self._error(
                    "R4",
                    f"Application to {record['finding_uuid']!r} names the unknown "
                    f"code-analysis run {record['analysis_run_id']!r}",
                )
        elif entity == "code_evidence":
            self._evidence.add(record["evidence_id"])
            if record.get('assessment_summary') or record.get('attachments'):
                self.has_evidence_material = True
            from ..code_evidence_services import validate_attachments, CodeEvidenceError
            try:
                validate_attachments(record.get('attachments', []))
            except CodeEvidenceError as exc:
                self._error('R4', str(exc))
        elif entity == "code_evidence_application":
            if record.get("team") or record.get("assessment_revision", -1) != -1 or record.get("selected", 1) != 1:
                self.has_evidence_material = True
            if record["evidence_id"] not in self._evidence:
                self._error(
                    "R4",
                    f"Application to {record['finding_uuid']!r} names the unknown "
                    f"code evidence {record['evidence_id']!r}",
                )
        elif entity == "source_snapshot":
            self._snapshots[(record["kind"], record["project_uuid"])] = (
                record["form"],
                record["item_count"],
            )
        elif entity in _LIST_ITEMS:
            project = "" if entity == "source_project" else record["project_uuid"]
            self._items[(_LIST_ITEMS[entity], project)] += 1

    def finish(
        self,
        sequences: dict[str, int],
        *,
        config_warnings: Iterable[Finding] = (),
    ) -> None:
        for (kind, project), count in sorted(self._items.items()):
            snapshot = self._snapshots.get((kind, project))
            if snapshot is None:
                self._error("R5", f"{count} {kind} items of {project!r} have no snapshot")
            elif snapshot[0] == "raw":
                self._error("R5", f"{count} {kind} items of {project!r} belong to a raw snapshot")
            elif snapshot[1] != count:
                self._error(
                    "R5",
                    f"The {kind} snapshot of {project!r} counts {snapshot[1]} items; "
                    f"{count} are present",
                )
        for (kind, project), (form, item_count) in sorted(self._snapshots.items()):
            if form == "list" and item_count and (kind, project) not in self._items:
                self._error(
                    "R5",
                    f"The {kind} snapshot of {project!r} counts {item_count} items; none are present",
                )
        for name, entity in (("assessment_revisions", "revision"), ("access_token_audit", "token_audit")):
            if sequences.get(name, 0) < self._max_ids[entity]:
                self._error(
                    "R6",
                    f"cut_point sequence {name} {sequences.get(name)} is below the "
                    f"largest id {self._max_ids[entity]}",
                )
        for key, (revision, status, _update_id) in self._assessments.items():
            if status in ("pending", "error") and key not in self._outbox:
                self._warn("W2", f"The {status} assessment {key!r} has no outbox entry")
            history = self._max_history.get(key)
            if history is None:
                self._warn("W6", f"The assessment {key!r} has no history")
            elif revision < history:
                self._warn(
                    "W4",
                    f"The assessment {key!r} is revision {revision}; its history reaches {history}",
                )
        self.warnings.extend(config_warnings)
        for entity, count in sorted(self.raw_counts.items()):
            self._warn("W8", raw_warning(entity, count))


def raw_warning(entity: str, count: int) -> str:
    field = "target_raw" if entity == "token_audit" else "payload_raw"
    return f"{count} {entity} record(s) keep a stored text that is not JSON as {field}"
