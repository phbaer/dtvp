"""Pinned coverage candidates, independent from assessment permissions or reuse."""

from collections import Counter

from dtvp.knowledge.assessments import component_lineage, coverage_status
from dtvp.knowledge.comparison import components, page, product_state, reachable_states
from dtvp.knowledge.metadata import identity_fingerprint
from dtvp.knowledge.ownership import product_heads
from dtvp.knowledge.version_selection import MAX_SELECTION_ROWS, select_versions
from dtvp.knowledge.workspace import load_sections
from dtvp.storage import canonical, digest

LIMITATIONS = [
    "Candidates are discovered only by exact source-local component references; names and PURLs never discover or merge occurrences.",
    "Matching material inputs do not establish verified context identity, applicability, reviewed coverage or permission.",
    "Different consuming roots remain separate contexts. Shared conclusions need explicit supporting conditions and independent review of each scope.",
    "Absent components or findings do not prove remediation. Retained assessments remain historical evidence.",
    "Version names are not ordered into ranges. New branches and changed builds never inherit approved coverage automatically.",
    "Candidate assessment summaries omit complete scope/evidence; exact revision pins bind the full records available through context detail.",
]


def _lineage(sections, context):
    try:
        return component_lineage(sections, context) if context else None
    except ValueError, TypeError:
        return None


def _identity_conflict(source, target, source_lineage, target_lineage):
    if source_lineage is None or target_lineage is None:
        return False
    if source_lineage.get("basis") == target_lineage.get("basis") == "source_local_refs":
        # Weak local refs cannot legitimize a producer recycling a ref for a
        # differently named package. Package version changes remain reviewable.
        return any(source.get(key) != target.get(key) for key in ("type", "name", "group"))
    return source_lineage != target_lineage


def _coverage_summary(coverage):
    result = {
        key: value
        for key, value in coverage.items()
        if key not in {"context", "assessment", "approved_assessment", "review"}
    }
    for key in ("assessment", "approved_assessment"):
        record = coverage.get(key)
        result[key] = (
            {
                "revision": record["revision"],
                "stage": record["stage"],
                "payload": {
                    name: record["payload"].get(name)
                    for name in (
                        "assessment_id",
                        "author_id",
                        "state",
                        "justification",
                        "rationale",
                        "conditions",
                    )
                },
            }
            if record
            else None
        )
    review = coverage.get("review")
    result["review"] = (
        {key: value for key, value in review.items() if key != "assessment"} if review else None
    )
    return result


def _row(source, sections, version, state, context, component, coverage, component_ref):
    selected = source["context"]
    context_id = context["id"] if context else selected["id"]
    lineage = _lineage(sections, context)
    same_context = bool(
        context
        and context["root_ref"] == selected["root_ref"]
        and context["component_ref"] == selected["component_ref"]
    )
    identity_equal = bool(component and identity_fingerprint(component) == source["identity"])
    lineage_compatible = bool(lineage and lineage == source["lineage"])
    conflict = bool(
        context
        and component
        and _identity_conflict(source["component"], component, source["lineage"], lineage)
    )
    material_equal = bool(
        coverage["fingerprint"] and coverage["fingerprint"] == source["fingerprint"]
    )
    reasons = []
    if component is None:
        availability, classification = "component_absent", "absent"
        reasons.append("exact_source_component_ref_not_reported")
    elif context is None:
        availability, classification = "context_missing", "unresolved"
        reasons.append("selected_consuming_context_not_reported")
    elif not coverage["fingerprint"]:
        availability = "finding_absent"
        classification = "identity_conflict" if conflict else "absent"
        reasons.append("vulnerability_not_reported_in_this_exact_context")
        if conflict:
            reasons.append("reused_source_component_ref_has_incompatible_identity")
    else:
        availability = "present"
        if conflict:
            classification = "identity_conflict"
            reasons.append("reused_source_component_ref_has_incompatible_identity")
        elif context.get("status") != "resolved":
            classification = "unresolved"
            reasons.append("target_ownership_or_dependency_topology_unresolved")
        elif not lineage_compatible:
            classification = "unresolved"
            reasons.append("component_lineage_compatibility_not_established")
        elif not same_context:
            classification = "different_context"
            reasons.append("different_consuming_root_requires_separate_applicability_assessment")
        elif material_equal:
            classification = "matching_material"
            reasons.append("same_local_context_references_and_material_inputs_only")
        else:
            classification = "material_changed"
            reasons.append("material_inputs_differ_explicit_applicability_review_required")
    if component and not identity_equal:
        reasons.append("exact_component_identity_facts_differ")
    if source["context"].get("status") != "resolved":
        reasons.append("selected_source_ownership_or_topology_is_unresolved")
    selector = {
        "version": version,
        "context_id": context_id,
        "vulnerability_id": source["vulnerability_id"],
    }
    return {
        "id": digest(canonical([state, selector, availability])),
        "state": state,
        "selector": selector,
        **selector,
        "component_ref": component_ref,
        "root_ref": context["root_ref"] if context else selected["root_ref"],
        "component": component,
        "context": context,
        "team_id": context.get("team_id") if context else None,
        "coverage": _coverage_summary(coverage),
        "coverage_detail": "summary",
        "availability": availability,
        "classification": classification,
        "assessment_candidate": bool(
            availability == "present"
            and context.get("status") == "resolved"
            and lineage_compatible
            and not conflict
        ),
        "conditions_required": True,
        "comparison": {
            "identity_equal": identity_equal,
            "identity_fingerprint": identity_fingerprint(component) if component else None,
            "same_context_references": same_context,
            "lineage": lineage,
            "lineage_compatible": lineage_compatible,
            "material_fingerprint": coverage["fingerprint"],
            "material_equal": material_equal,
            "equivalence": "source_local_material_match"
            if same_context and material_equal and identity_equal and not conflict
            else "not_established",
        },
        "reasons": reasons,
    }


def coverage_candidates(
    journal,
    project_id,
    source,
    context_id,
    vulnerability_id,
    offset=0,
    limit=50,
    *,
    version_selection=None,
):
    """Read all current version heads from one reference snapshot, then paginate."""
    page([], offset, limit)
    references = journal.references()
    revision = journal.verify_state(source)
    product_state(journal, source, project_id)
    heads = dict(sorted(product_heads(references, project_id).items()))
    selection = select_versions(heads, version_selection) if version_selection is not None else None
    selected_versions = set(selection["selected_versions"]) if selection else set(heads)
    if source not in heads.values() and source not in reachable_states(
        journal, project_id, references=references
    ):
        raise ValueError("Source must be a committed product state in this product line")
    sections_cache = {}
    coverage_cache = {}

    def sections_for(state):
        if state not in sections_cache:
            sections_cache[state] = load_sections(journal, state)
        return sections_cache[state]

    def coverage_for(state, version, selected_context):
        key = (state, version, selected_context)
        if key not in coverage_cache:
            coverage_cache[key] = coverage_status(
                journal, sections_for(state), version, selected_context, vulnerability_id
            )
        return coverage_cache[key]

    original = sections_for(source)
    context = original["ownership"].get("context:" + context_id)
    source_components = components(original["inventory"])
    component = source_components.get(context["component_ref"]) if context else None
    coverage = coverage_for(source, revision.version, context_id)
    if not context or not component or not coverage["fingerprint"]:
        raise ValueError("Selected source contextual finding is absent")
    selected = {
        "state": source,
        "version": revision.version,
        "context_id": context_id,
        "vulnerability_id": vulnerability_id,
        "context": context,
        "component": component,
        "identity": identity_fingerprint(component),
        "lineage": _lineage(original, context),
        "fingerprint": coverage["fingerprint"],
        "coverage": coverage,
    }
    rows = []
    for version, state in heads.items():
        if version not in selected_versions:
            continue
        current_revision = journal.verify_state(state)
        if current_revision.project_id != project_id or current_revision.version != version:
            raise ValueError("Current product branch head has incompatible identity")
        current = sections_for(state)
        current_component = components(current["inventory"]).get(context["component_ref"])
        contexts = (
            [
                item
                for key, item in sorted(current["ownership"].items())
                if key.startswith("context:")
                and item.get("component_ref") == context["component_ref"]
            ]
            if current_component
            else []
        )
        if not any(item["id"] == context_id for item in contexts):
            contexts.append(None)
        for candidate in contexts:
            if selection and len(rows) >= MAX_SELECTION_ROWS:
                raise ValueError("Version selection exceeds the complete 1000-context budget")
            candidate_id = candidate["id"] if candidate else context_id
            rows.append(
                _row(
                    selected,
                    current,
                    version,
                    state,
                    candidate,
                    current_component,
                    coverage_for(state, version, candidate_id),
                    context["component_ref"],
                )
            )
    rows.sort(key=lambda row: (row["version"], row["root_ref"], row["context_id"]))
    result = {
        "format": "dtvp.coverage-candidates/1",
        "project_id": project_id,
        "source": selected,
        "heads": heads,
        "statistics": {
            "versions": len(selected_versions),
            "rows": len(rows),
            "assessment_candidates": sum(row["assessment_candidate"] for row in rows),
            "by_classification": dict(Counter(row["classification"] for row in rows)),
            "by_availability": dict(Counter(row["availability"] for row in rows)),
            "by_coverage": dict(Counter(row["coverage"]["status"] for row in rows)),
        },
        "limitations": LIMITATIONS,
    }
    if selection is not None:
        result["version_selection"] = selection
        result["limitations"] = [
            item for item in LIMITATIONS if not item.startswith("Version names")
        ] + [selection["semantics"]]
    result["preview_digest"] = digest(canonical([result, rows]))
    return {**result, **page(rows, offset, limit)}
