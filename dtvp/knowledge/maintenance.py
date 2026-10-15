"""Read-only retention planning; never delete journal objects or approvals."""

from collections import Counter
from datetime import UTC, datetime

from dtvp.knowledge.assessments import Target, load_sections
from dtvp.knowledge.comparison import product_state
from dtvp.knowledge.journal import Ref
from dtvp.storage import canonical, digest

LIMITATIONS = [
    "Candidates are absent from every current product branch, not proven obsolete or safe to delete.",
    "Release tags protect exact referenced revisions; immutable journal history remains retained.",
    "Unknown or malformed scope is never a retention candidate; no physical storage estimate is made.",
    "This preview changes no references, assessment records, approvals or stored objects.",
    "Age is measured from revision authorship, not from disappearance or last use.",
]


def _age(value, now):
    try:
        created = datetime.fromisoformat(value)
        if created.tzinfo is None or created > now:
            return None
        return (now - created).days
    except ValueError, TypeError:
        return None


def _targets(payload):
    values = payload.get("targets")
    if not isinstance(values, list) or not values:
        return None
    try:
        return [
            Target.model_validate({key: item[key] for key in Target.model_fields})
            for item in values
        ]
    except ValueError, TypeError, KeyError:
        return None


def _present(sections, target):
    context = sections["ownership"].get("context:" + target.context_id)
    return bool(context) and any(
        item.get("ref") == context.get("component_ref")
        and item.get("identifier") == target.vulnerability_id
        for item in sections["vulnerabilities"].values()
    )


def preview_retention(journal, project_id, *, offset=0, limit=50, now=None):
    """Pin complete product heads, inspect current pointers and retained review pins.

    Revisions replaced everywhere without a current assessment/review pointer are
    outside this bounded preview. Historical parents are never GC candidates.
    Callers enforce product-level authorization before exposing the full plan.
    """
    if offset < 0 or not 1 <= limit <= 200:
        raise ValueError("Invalid maintenance page bounds")
    now = now or datetime.now(UTC)
    if now.tzinfo is None:
        raise ValueError("Preview time must include a timezone")
    refs = (
        journal.references()
    )  # One committed reference snapshot, even during concurrent publication.
    branches, tags = {}, {}
    for key, state in sorted(refs.items()):
        ref = Ref.model_validate_json(key)
        if ref.project_id != project_id or ref.kind not in {"branch", "tag"}:
            continue
        try:
            product_state(journal, state, project_id)
        except ValueError:
            continue
        target = branches if ref.kind == "branch" else tags
        target[ref.name] = {"state": state, "sections": load_sections(journal, state)}
    records = {}

    def remember(assessment_id, revision, payload, kind, name):
        if not assessment_id or not revision or not isinstance(payload, dict):
            # Keep malformed pointers visible under an explicit unknown identifier.
            assessment_id = assessment_id or "unknown"
            revision = revision or "unknown"
            payload = payload if isinstance(payload, dict) else {}
        key = (assessment_id.removeprefix("assessment:"), revision)
        entry = records.setdefault(key, {"payload": payload, "branches": set(), "tags": set()})
        if entry["payload"] != payload:
            entry["conflict"] = True
        entry[kind].add(name)

    for kind, selections in (("branches", branches), ("tags", tags)):
        for name, selected in selections.items():
            sections = selected["sections"]
            for key, record in sections["assessments"].items():
                remember(key, record.get("revision"), record.get("payload"), kind, name)
            for record in sections["reviews"].values():
                remember(
                    record.get("assessment_id"),
                    record.get("assessment_revision"),
                    record.get("assessment"),
                    kind,
                    name,
                )
    items = []
    for (assessment_id, revision), entry in sorted(records.items()):
        payload = entry["payload"]
        targets = _targets(payload)
        active = []
        if targets:
            for target in targets:
                selected = branches.get(target.version)
                if selected and _present(selected["sections"], target):
                    active.append(target.model_dump())
        unknown = targets is None or entry.get("conflict", False)
        protected = bool(entry["tags"])
        status = (
            "unknown_scope"
            if unknown
            else "active"
            if active
            else "tag_protected"
            if protected
            else "retention_candidate"
        )
        items.append(
            {
                "assessment_id": assessment_id,
                "revision": revision,
                "status": status,
                "candidate": status == "retention_candidate",
                "current_branches": sorted(entry["branches"]),
                "tagged_references": sorted(entry["tags"]),
                "active_targets": active,
                "targets": [target.model_dump() for target in targets] if targets else [],
                "created_at": payload.get("created_at"),
                "retained_age_days": _age(payload.get("created_at"), now),
            }
        )
    logical = []
    for assessment_id in sorted({item["assessment_id"] for item in items}):
        revisions = [item for item in items if item["assessment_id"] == assessment_id]
        counts = Counter(item["status"] for item in revisions)
        status = next(
            (value for value in ("unknown_scope", "active", "tag_protected") if counts[value]),
            "retention_candidate",
        )
        logical.append(
            {
                "assessment_id": assessment_id,
                "status": status,
                "candidate": status == "retention_candidate",
                "revisions": [item["revision"] for item in revisions],
            }
        )
    heads = {name: value["state"] for name, value in branches.items()}
    protected_heads = {name: value["state"] for name, value in tags.items()}
    # Time, page bounds and derived age do not change a plan pinned to identical facts.
    plan = {
        "format": "dtvp.retention-preview/1",
        "project_id": project_id,
        "branch_heads": heads,
        "tag_heads": protected_heads,
        "revisions": [
            {key: value for key, value in item.items() if key != "retained_age_days"}
            for item in items
        ],
        "assessments": logical,
    }
    return {
        "format": plan["format"],
        "project_id": project_id,
        "plan_hash": digest(canonical(plan)),
        "branch_heads": heads,
        "tag_heads": protected_heads,
        "items": items[offset : offset + limit],
        "total": len(items),
        "next_offset": offset + limit if offset + limit < len(items) else None,
        "statistics": {
            "revision_statuses": dict(Counter(item["status"] for item in items)),
            "logical_statuses": dict(Counter(item["status"] for item in logical)),
            "revisions": len(items),
            "logical_assessments": len(logical),
            "unknown_age": sum(item["retained_age_days"] is None for item in items),
        },
        "assessments": logical[offset : offset + limit],
        "logical_total": len(logical),
        "logical_next_offset": offset + limit if offset + limit < len(logical) else None,
        "limitations": list(LIMITATIONS),
    }
