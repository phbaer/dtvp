"""Explicit logical retirement; immutable assessment/review evidence remains readable."""

from collections import Counter
from datetime import UTC, datetime

from pydantic import Field, model_validator

from dtvp.knowledge.assessments import load_sections, prepare
from dtvp.knowledge.journal import (
    SECTIONS,
    Conflict,
    CorruptJournal,
    Name,
    Ref,
    Revision,
    Section,
    Sha,
    Update,
)
from dtvp.knowledge.maintenance import _targets
from dtvp.knowledge.scoring import published_score
from dtvp.schemas import RequestModel
from dtvp.storage import canonical, digest

MAX_STATES = 10_000
MAX_POINTERS = 100_000
MAX_SCAN_BYTES = 64 * 1024 * 1024
FORMAT = "dtvp.assessment-archive/1"
LIMITATIONS = [
    "Logical retirement removes current assessment/review pointers, not immutable history or physical storage.",
    "Only wholly absent logical assessments with known scope and no exact tagged protection may retire.",
    "Retired IDs cannot be edited or reused; explicit forks may retain historical pointers without cross-version approval.",
    "No license, document, scoring, source facts, historical approvals or tags are deleted.",
    "A complete historical scan is required; exceeding configured finite caps fails closed.",
]


class ArchiveInput(RequestModel):
    request_id: Name
    plan_hash: Sha
    project_refs: dict[str, Sha] = Field(max_length=20_000)
    assessment_ids: list[Name] = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=1, max_length=6000)

    @model_validator(mode="after")
    def distinct(self):
        if not self.reason.strip():
            raise ValueError("Archival requires a nonblank reason")
        if len(set(self.assessment_ids)) != len(self.assessment_ids):
            raise ValueError("Select distinct logical assessment identifiers")
        return self


def archive_ref(project_id):
    return Ref(kind="policy", project_id=project_id, name="assessment-archive")


def archive_key(assessment_id):
    return "archive:" + digest(canonical(assessment_id))


def is_retired(journal, archive_state, assessment_id):
    return bool(
        archive_state and archive_key(assessment_id) in journal.records(archive_state, "history")
    )


def project_references(journal, project_id):
    return {
        key: state
        for key, state in journal.references().items()
        if Ref.model_validate_json(key).project_id == project_id
    }


def _plan(journal, project_id):
    refs = project_references(journal, project_id)
    if len(refs) > 20_000:
        raise ValueError("Assessment archival exceeds complete project-reference cap")
    # Bound traversal itself, not only the final result. History never silently truncates.
    product_refs = [
        (Ref.model_validate_json(key), state)
        for key, state in refs.items()
        if Ref.model_validate_json(key).kind in {"branch", "tag"}
    ]
    pending = [state for _, state in product_refs]
    states, seen, cache, record_shas = {}, set(), {}, {}
    decoded_bytes = 0

    def bounded_load(sha):
        nonlocal decoded_bytes
        if sha not in cache:
            try:
                size = journal.objects.path(sha).stat().st_size
            except OSError as error:
                raise CorruptJournal("Missing archival scan object") from error
            if decoded_bytes + size > MAX_SCAN_BYTES:
                raise ValueError(
                    "Assessment archival exceeds complete-history 64 MiB decoded-input budget"
                )
            decoded_bytes += size
            cache[sha] = journal.load(
                sha
            )  # Still hash verifies every newly decoded immutable object.
        return cache[sha]

    while pending:
        sha = pending.pop()
        if sha in seen:
            continue
        seen.add(sha)
        if len(seen) > MAX_STATES:
            raise ValueError("Assessment archival exceeds complete-history state cap")
        revision = Revision.model_validate(bounded_load(sha))
        if revision.project_id != project_id:
            raise CorruptJournal("Cross-project historical parent blocks archival")
        if revision.version.startswith("@"):
            continue
        indices = {
            "inventory": Section.model_validate(
                bounded_load(revision.sections["inventory"])
            ).records
        }
        baseline_sha = indices["inventory"].get("baseline")
        baseline = bounded_load(baseline_sha) if baseline_sha else None
        if baseline is None:
            raise ValueError("Historical state has unknown product scope; archival blocked")
        if baseline.get("part_id"):
            continue
        for name in SECTIONS:
            if name not in indices:
                indices[name] = Section.model_validate(
                    bounded_load(revision.sections[name])
                ).records
        sections = {
            name: {key: bounded_load(record) for key, record in indices[name].items()}
            for name in SECTIONS
        }
        states[sha] = (revision, sections)
        record_shas[sha] = indices
        pending.extend(revision.parents)
    branches = {
        ref.name: state for ref, state in product_refs if ref.kind == "branch" and state in states
    }
    tags = {ref.name: state for ref, state in product_refs if ref.kind == "tag" and state in states}
    active_scopes = {}
    for version, sha in branches.items():
        sections = states[sha][1]
        identifiers = {}
        for finding in sections["vulnerabilities"].values():
            identifiers.setdefault(finding.get("ref"), set()).add(finding.get("identifier"))
        active_scopes[version] = {
            (key.removeprefix("context:"), identifier)
            for key, context in sections["ownership"].items()
            if key.startswith("context:")
            for identifier in identifiers.get(context.get("component_ref"), ())
        }
    score_cache = {}
    records, occurrences, unknown_ids = {}, {}, set()
    grouped, tag_pins = {}, {}
    tag_names = {}
    for name, state in tags.items():
        tag_names.setdefault(state, set()).add(name)
    pointers = 0
    for state, (_, sections) in sorted(states.items()):
        for section in ("assessments", "reviews"):
            for key, record in sorted(sections[section].items()):
                pointers += 1
                if pointers > MAX_POINTERS:
                    raise ValueError("Assessment archival exceeds complete-history pointer cap")
                assessment_id = (
                    key.removeprefix("assessment:")
                    if section == "assessments"
                    else record.get("assessment_id")
                    if isinstance(record, dict)
                    else None
                )
                if not isinstance(assessment_id, str) or not assessment_id:
                    raise ValueError(
                        "Unattributable historical assessment/review pointer blocks archival"
                    )
                revision = (
                    record.get("revision" if section == "assessments" else "assessment_revision")
                    if isinstance(record, dict)
                    else None
                )
                if not isinstance(revision, str):
                    revision = None
                payload = (
                    record.get("payload" if section == "assessments" else "assessment")
                    if isinstance(record, dict)
                    else None
                )
                if (
                    not isinstance(payload, dict)
                    or not revision
                    or digest(canonical(payload)) != revision
                    or payload.get("format") != "dtvp.assessment/1"
                    or payload.get("assessment_id") != assessment_id
                    or payload.get("project_id") != project_id
                ):
                    unknown_ids.add(assessment_id)
                if isinstance(record, dict) and (
                    (section == "assessments" and record.get("stage") not in {"draft", "submitted"})
                    or (
                        section == "reviews"
                        and (
                            record.get("format") != "dtvp.review/1"
                            or record.get("status") not in {"approved", "changes_requested"}
                        )
                    )
                ):
                    unknown_ids.add(assessment_id)
                identity = (assessment_id, revision)
                if identity in records and records[identity] != payload:
                    unknown_ids.add(assessment_id)
                records[identity] = payload
                grouped.setdefault(assessment_id, {})[revision] = payload
                tag_pins.setdefault(identity, set()).update(tag_names.get(state, set()))
                occurrences.setdefault(assessment_id, []).append(
                    {
                        "state": state,
                        "section": section,
                        "key": key,
                        "record_sha": record_shas[state][section][key],
                        "revision": revision,
                    }
                )
    archive_state = refs.get(archive_ref(project_id).key)
    retired_keys = set()
    if archive_state:
        archive_revision = Revision.model_validate(bounded_load(archive_state))
        retired_keys = set(
            Section.model_validate(bounded_load(archive_revision.sections["history"])).records
        )
    logical, revisions = [], []
    for assessment_id in sorted(occurrences):
        unknown, active, protected, scoring = assessment_id in unknown_ids, [], set(), False
        known_revisions = []
        for revision, payload in grouped[assessment_id].items():
            targets = _targets(payload) if isinstance(payload, dict) else None
            if targets is None:
                unknown = True
            for target in targets or []:
                if target.version not in branches:
                    unknown = True
                    continue
                sections = states[branches[target.version]][1]
                if (target.context_id, target.vulnerability_id) in active_scopes[target.version]:
                    active.append(target.model_dump())
                try:
                    score_target = (target.version, target.context_id, target.vulnerability_id)
                    if score_target not in score_cache:
                        score_cache[score_target] = published_score(
                            journal, sections, *score_target
                        )
                    score = score_cache[score_target]
                    scoring = scoring or bool(score and score["current"])
                except KeyError, TypeError, ValueError:
                    unknown = True
            tagged = sorted(tag_pins.get((assessment_id, revision), set()))
            protected.update(tagged)
            known_revisions.append(revision)
            revisions.append(
                {
                    "assessment_id": assessment_id,
                    "revision": revision,
                    "targets": [item.model_dump() for item in targets or []],
                    "tagged_references": tagged,
                }
            )
        retired = archive_key(assessment_id) in retired_keys
        status = (
            "unknown_scope"
            if unknown
            else "active"
            if active
            else "tag_protected"
            if protected
            else "current_scoring_reference"
            if scoring
            else "already_archived"
            if retired
            else "retention_candidate"
        )
        logical.append(
            {
                "assessment_id": assessment_id,
                "status": status,
                "candidate": status == "retention_candidate",
                "revisions": sorted(item for item in known_revisions if item),
                "active_targets": sorted(active, key=canonical),
                "tagged_references": sorted(protected),
                "current_branches": sorted(
                    version
                    for version, sha in branches.items()
                    if any(item["state"] == sha for item in occurrences[assessment_id])
                ),
            }
        )
    plan = {
        "format": "dtvp.assessment-archive-preview/1",
        "project_id": project_id,
        "project_refs": refs,
        "assessments": logical,
        "revisions": sorted(revisions, key=canonical),
    }
    plan["plan_hash"] = digest(canonical(plan))
    return plan, states, branches, records, occurrences


def preview_archive(journal, project_id, *, offset=0, limit=50):
    if offset < 0 or not 1 <= limit <= 200:
        raise ValueError("Invalid archive page bounds")
    plan, *_ = _plan(journal, project_id)
    items = plan["assessments"]
    return {
        **plan,
        "assessments": items[offset : offset + limit],
        "revisions": plan["revisions"][offset : offset + limit],
        "total": len(items),
        "revision_total": len(plan["revisions"]),
        "statistics": dict(Counter(item["status"] for item in items)),
        "next_offset": offset + limit
        if offset + limit < max(len(items), len(plan["revisions"]))
        else None,
        "limitations": list(LIMITATIONS),
    }


def apply_archive(journal, *, project_id, actor_id, data):
    request_id, fingerprint, receipt = prepare(
        journal, project_id, actor_id, "assessment.archive/1", data.model_dump(mode="json")
    )
    if receipt:
        return receipt
    plan, states, branches, records, occurrences = _plan(journal, project_id)
    if plan["plan_hash"] != data.plan_hash or plan["project_refs"] != data.project_refs:
        raise Conflict("Assessment archive plan changed; preview again")
    eligible = {item["assessment_id"] for item in plan["assessments"] if item["candidate"]}
    if not set(data.assessment_ids) <= eligible:
        raise Conflict(
            "Every selected logical assessment must be an unprotected retention candidate"
        )
    ref = archive_ref(project_id)
    previous = data.project_refs.get(ref.key)
    archived = load_sections(journal, previous) if previous else {name: {} for name in SECTIONS}
    artifacts = set(journal.state(previous).artifacts if previous else [])
    manifests = {}
    for assessment_id in data.assessment_ids:
        manifests[assessment_id] = {
            "format": FORMAT,
            "project_id": project_id,
            "assessment_id": assessment_id,
            "actor_id": actor_id,
            "reason": data.reason,
            "archived_at": datetime.now(UTC).isoformat(),
            "revisions": sorted(
                revision for identifier, revision in records if identifier == assessment_id
            ),
            "occurrences": occurrences[assessment_id],
            "plan_hash": data.plan_hash,
        }
        manifest_sha = journal.store(manifests[assessment_id])
        archived["history"][archive_key(assessment_id)] = {
            "format": "dtvp.assessment-archive-pointer/1",
            "assessment_id": assessment_id,
            "manifest_sha": manifest_sha,
            "actor_id": actor_id,
            "reason": data.reason,
            "archived_at": manifests[assessment_id]["archived_at"],
            "revision_count": len(manifests[assessment_id]["revisions"]),
        }
        artifacts.add(manifest_sha)
        artifacts.update(manifests[assessment_id]["revisions"])
        artifacts.update(item["record_sha"] for item in occurrences[assessment_id])
    archive_state = journal.snapshot(
        project_id=project_id,
        version="@assessment-archive",
        actor_id=actor_id,
        reason="Archive unused contextual assessments",
        sections=archived,
        parents=sorted(set(([previous] if previous else []) + list(branches.values()))),
        artifacts=sorted(artifacts),
    )
    updates = [Update(ref=ref, expected=previous, target=archive_state)]
    for version, parent in sorted(branches.items()):
        sections = {name: dict(items) for name, items in states[parent][1].items()}
        removed = [
            key
            for key in sections["assessments"]
            if key.removeprefix("assessment:") in data.assessment_ids
        ]
        reviews = [
            key
            for key, item in sections["reviews"].items()
            if item.get("assessment_id") in data.assessment_ids
        ]
        if not removed and not reviews:
            continue
        for key in removed:
            del sections["assessments"][key]
        for key in reviews:
            del sections["reviews"][key]
        for assessment_id in data.assessment_ids:
            if any(item["state"] == parent for item in occurrences[assessment_id]):
                sections["history"]["assessment-archive:" + digest(canonical(assessment_id))] = {
                    "format": "dtvp.assessment-archive-link/1",
                    "assessment_id": assessment_id,
                    "archive_state": archive_state,
                }
        state = journal.snapshot(
            project_id=project_id,
            version=version,
            actor_id=actor_id,
            reason="Archive unused contextual assessments",
            sections=sections,
            parents=[parent, archive_state],
            artifacts=journal.state(parent).artifacts,
        )
        updates.append(
            Update(ref=Ref(project_id=project_id, name=version), expected=parent, target=state)
        )
    return journal.publish(
        request_id=request_id,
        fingerprint=fingerprint,
        updates=updates,
        project_refs={project_id: data.project_refs},
    )


def list_archived(journal, project_id, *, offset=0, limit=50):
    if offset < 0 or not 1 <= limit <= 200:
        raise ValueError("Invalid archive page bounds")
    state = journal.resolve(archive_ref(project_id))
    records = journal.records(state, "history") if state else {}
    keys = sorted(records)
    items = [journal.load(records[key]) for key in keys[offset : offset + limit]]
    return {
        "archive_state": state,
        "items": items,
        "total": len(keys),
        "next_offset": offset + limit if offset + limit < len(keys) else None,
        "limitations": list(LIMITATIONS),
    }


def get_archived(journal, project_id, assessment_id, *, offset=0, limit=50):
    if offset < 0 or not 1 <= limit <= 200:
        raise ValueError("Invalid archive page bounds")
    state = journal.resolve(archive_ref(project_id))
    records = journal.records(state, "history") if state else {}
    key = archive_key(assessment_id)
    if key not in records:
        raise KeyError(assessment_id)
    pointer = journal.load(records[key])
    manifest = journal.load(pointer["manifest_sha"])
    return {
        "archive_state": state,
        "manifest": {
            key: value for key, value in manifest.items() if key not in {"occurrences", "revisions"}
        },
        "revision_total": len(manifest["revisions"]),
        "record_total": len(manifest["occurrences"]),
        "next_offset": offset + limit
        if offset + limit < max(len(manifest["revisions"]), len(manifest["occurrences"]))
        else None,
        "assessments": [
            {"revision": sha, "payload": journal.load(sha)}
            for sha in manifest["revisions"][offset : offset + limit]
        ],
        "records": [
            {**item, "record": journal.load(item["record_sha"])}
            for item in manifest["occurrences"][offset : offset + limit]
        ],
        "current_approval": False,
    }
