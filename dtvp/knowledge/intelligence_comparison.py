"""Read-only known-ID advisory comparison against immutable product composition."""

from collections import Counter

from pydantic import Field

from dtvp.knowledge.evidence import evidence_ref
from dtvp.knowledge.journal import CorruptJournal, Ref, Revision, Section, Sha
from dtvp.schemas import RequestModel
from dtvp.storage import canonical, digest

MAX_STATES = 10_000
MAX_DOCUMENTS = 10_000
MAX_RECORDS = 20_000
MAX_CLAIMS = 10_000
MAX_BYTES = 64 * 1024 * 1024
LIMITATIONS = [
    "Only exact vulnerability identifiers reported by the pinned baseline composition are considered; no package matching, aliases or new findings are inferred.",
    "This compares retained advisory-feed claims only. VDR/VEX status documents are excluded and never applied to the pinned inventory.",
    "Removed or inactive selections do not establish publisher retraction, remediation, absence of vulnerability or applicability.",
    "Descriptions, ratings and raw provider facts remain attributed unverified claims; no Base, human assessment, approval or contextual score is changed.",
    "Artifact hashes are retained source pins; this report does not download or verify every original provider artifact byte.",
    "The report digest binds immutable selected inputs and full rows; live evidence currentness is separate and may change without altering that digest.",
]


class IntelligenceInput(RequestModel):
    inventory_state: Sha
    evidence_state: Sha | None = Field(...)
    expected_digest: Sha | None = None


class Scan:
    def __init__(self, journal):
        self.journal, self.cache, self.bytes = journal, {}, 0
        self.states = set()

    def load(self, sha):
        if sha not in self.cache:
            try:
                size = self.journal.objects.path(sha).stat().st_size
            except OSError as error:
                raise CorruptJournal("Missing comparison object") from error
            if size + self.bytes > MAX_BYTES:
                raise ValueError("Intelligence comparison exceeds the 64 MiB decoded-input budget")
            value = self.journal.load(sha)
            self.bytes += size
            self.cache[sha] = value
        return self.cache[sha]

    def revision(self, sha):
        if sha not in self.states:
            if len(self.states) >= MAX_STATES:
                raise ValueError("Intelligence comparison exceeds the 10000-state budget")
            self.states.add(sha)
        return Revision.model_validate(self.load(sha))

    def records(self, revision, section):
        records = Section.model_validate(self.load(revision.sections[section])).records
        if len(records) > MAX_RECORDS:
            raise ValueError("Intelligence comparison exceeds the 20000-record section budget")
        return records

    def admit(self, roots, wanted, project_id, *, evidence=False):
        pending, seen = list(roots), set()
        if len(pending) > MAX_STATES:
            raise ValueError("Intelligence comparison exceeds the 10000-state budget")
        while pending:
            state = pending.pop()
            if state in seen:
                continue
            seen.add(state)
            revision = self.revision(state)
            if revision.project_id != project_id:
                raise CorruptJournal("Comparison ancestry crosses product scope")
            if evidence:
                if revision.version != "@evidence":
                    raise CorruptJournal("Evidence ancestry has incompatible scope")
            else:
                if revision.version.startswith("@"):
                    continue
                inventory = self.records(revision, "inventory")
                baseline = self.load(inventory["baseline"]) if "baseline" in inventory else None
                if baseline is None or baseline.get("part_id"):
                    continue
            if state == wanted:
                return revision
            if len(pending) + len(revision.parents) > MAX_STATES:
                raise ValueError("Intelligence comparison exceeds the 10000-state frontier budget")
            pending.extend(revision.parents)
        raise KeyError("Selected input is not retained in this product line")


def _documents(scan, revision):
    if revision is None:
        return []
    records = scan.records(revision, "vulnerabilities")
    selected = [sha for key, sha in records.items() if key.startswith("evidence-document:")]
    if len(selected) > MAX_DOCUMENTS:
        raise ValueError("Intelligence comparison exceeds the 10000-document budget")
    return [scan.load(sha) for sha in selected]


def _claims(documents, known_ids):
    active, inactive, excluded, ignored = {}, {}, Counter(), 0
    statements = 0
    for record in documents:
        document = record["document"]
        if document["format"] != "dtvp.advisory-feed/1":
            excluded[document["format"]] += 1
            continue
        for item in document["statements"]:
            statements += 1
            if statements > MAX_CLAIMS:
                raise ValueError("Intelligence comparison exceeds the 10000-statement budget")
            identifier = item["vulnerability_id"]
            if identifier not in known_ids:
                ignored += 1
                continue
            key = (record["source"], document.get("publisher"), document["document_id"], identifier)
            observation = {
                "artifact_sha": record["artifact_sha"],
                "source_revision": record["source_revision"],
                "facts": item["raw"],
                "selection": "active" if record.get("active", True) else "inactive",
                "superseded_by": record.get("superseded_by"),
                "withdrawal": record.get("withdrawal"),
            }
            destination = active if record.get("active", True) else inactive
            destination.setdefault(key, []).append(observation)
    for values in (*active.values(), *inactive.values()):
        values.sort(key=canonical)
    return active, inactive, dict(excluded), ignored


def compare_intelligence(journal, project_id, data, *, offset=0, limit=50):
    if offset < 0 or not 1 <= limit <= 200:
        raise ValueError("Invalid intelligence comparison page bounds")
    refs = journal.references()
    roots = [
        state
        for key, state in refs.items()
        if (ref := Ref.model_validate_json(key)).project_id == project_id
        and ref.kind in {"branch", "tag"}
    ]
    scan = Scan(journal)
    baseline = scan.admit(roots, data.inventory_state, project_id)
    current = refs.get(evidence_ref(project_id).key)
    selected = (
        scan.admit([current] if current else [], data.evidence_state, project_id, evidence=True)
        if data.evidence_state is not None
        else None
    )
    claims = scan.records(baseline, "vulnerabilities")
    baseline_refs = {}
    for key, sha in claims.items():
        if key.startswith(("evidence-document:", "external-evidence:")):
            continue
        claim = scan.load(sha)
        if claim.get("identifier") and claim.get("ref"):
            baseline_refs.setdefault(claim["identifier"], set()).add(claim["ref"])
    before, _, before_excluded, before_ignored = _claims(_documents(scan, baseline), baseline_refs)
    after, inactive, after_excluded, after_ignored = _claims(
        _documents(scan, selected), baseline_refs
    )
    identities = set(before) | set(after)
    if len(identities) > MAX_CLAIMS:
        raise ValueError("Intelligence comparison exceeds the 10000-claim budget")
    rows = []
    for key in sorted(identities, key=canonical):
        old, new = before.get(key, []), after.get(key, [])
        old_facts = sorted((item["facts"] for item in old), key=canonical)
        new_facts = sorted((item["facts"] for item in new), key=canonical)
        status = (
            "added"
            if not old
            else "withdrawn_from_selection"
            if not new and key in inactive
            else "no_longer_selected"
            if not new
            else "unchanged"
            if old_facts == new_facts
            else "changed"
        )
        rows.append(
            {
                "id": digest(canonical(key)),
                "source": key[0],
                "publisher": key[1],
                "document_id": key[2],
                "vulnerability_id": key[3],
                "component_refs": sorted(baseline_refs[key[3]]),
                "status": status,
                "before": old,
                "after": new,
                "inactive_selected_records": inactive.get(key, []) if not new else [],
            }
        )
    report = {
        "format": "dtvp.intelligence-comparison/1",
        "project_id": project_id,
        "inventory_state": data.inventory_state,
        "inventory_version": baseline.version,
        "evidence_state": data.evidence_state,
        "statistics": {
            "baseline_identifiers": len(baseline_refs),
            "claim_groups": len(rows),
            "by_status": dict(Counter(row["status"] for row in rows)),
            "excluded_document_formats": {"before": before_excluded, "after": after_excluded},
            "nonbaseline_statements": {"before": before_ignored, "after": after_ignored},
        },
        "limitations": list(LIMITATIONS),
    }
    report_digest = digest(canonical([report, rows]))
    if data.expected_digest is not None and data.expected_digest != report_digest:
        from dtvp.knowledge.journal import Conflict

        raise Conflict("Pinned intelligence comparison differs from the expected digest")
    return {
        **report,
        "report_digest": report_digest,
        "currentness": {
            "captured_evidence_head": current,
            "selected_is_current": data.evidence_state == current,
        },
        "items": rows[offset : offset + limit],
        "total": len(rows),
        "next_offset": offset + limit if offset + limit < len(rows) else None,
    }
