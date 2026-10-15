"""Read-only assessment synchronization proposals over immutable product states."""

from collections import Counter

from dtvp.knowledge.assessments import component_lineage, coverage_status
from dtvp.knowledge.comparison import page, reachable_states
from dtvp.knowledge.workspace import load_sections
from dtvp.storage import canonical, digest

_NO_BASIS = object()


def _content(record):
    if not record:
        return None
    payload = record.get("payload", {})
    return {
        key: payload.get(key)
        for key in ("state", "justification", "rationale", "conditions", "evidence")
    }


def _record(coverage):
    return coverage.get("assessment") or coverage.get("approved_assessment")


def _assessment_summary(coverage):
    record = _record(coverage)
    return {
        "status": coverage["status"],
        "approved": bool(
            record
            and coverage.get("approved")
            and record["revision"] == coverage.get("assessment_revision")
        ),
        "assessment_revision": record.get("revision") if record else None,
        "assessment": record,
        "fingerprint": coverage.get("fingerprint"),
        "approved_revision": (coverage.get("approved_assessment") or {}).get("revision"),
    }


def _ancestors(state, revisions):
    seen, pending = set(), [state]
    while pending:
        current = pending.pop()
        if current in seen or current not in revisions:
            continue
        seen.add(current)
        pending.extend(revisions[current].parents)
    return seen


def _provenance(sections):
    return {key: sections["inventory"].get(key) for key in ("baseline", "assembly")}


def _scopes(sections, version):
    result, unknown = set(), []
    for key, record in sorted(sections["assessments"].items()):
        targets = record.get("payload", {}).get("targets", [])
        if not targets:
            unknown.append((key, record))
        for target in targets:
            if (
                target.get("version") == version
                and target.get("context_id")
                and target.get("vulnerability_id")
            ):
                result.add((target["context_id"], target["vulnerability_id"]))
    for review in sections["reviews"].values():
        target = review.get("target", {})
        if (
            target.get("version") == version
            and target.get("context_id")
            and target.get("vulnerability_id")
        ):
            result.add((target["context_id"], target["vulnerability_id"]))
    return sorted(result), unknown


def _classify(
    source,
    target,
    source_context,
    target_context,
    source_record,
    source_coverage,
    target_coverage,
    basis_source,
    basis_target,
):
    if not source_context or not source_coverage.get("fingerprint") or not source_record:
        return "unresolved", ["source_assessment_scope_or_current_evidence_unavailable"]
    if source_coverage["status"] == "reassessment_needed":
        return "needs_review", ["source_assessment_requires_revalidation"]
    if target_context is None:
        ref = source_context["component_ref"]
        present = any(item.get("bom-ref") == ref for item in target["inventory"].values())
        return (
            ("unresolved", ["target_consuming_context_missing"])
            if present
            else (
                "not_applicable",
                ["component_not_reported_in_target_state_not_remediation_proof"],
            )
        )
    if not target_coverage.get("fingerprint"):
        return "not_applicable", [
            "vulnerability_not_reported_in_target_context_not_remediation_proof"
        ]
    if target_context.get("status") != "resolved" or source_context.get("status") != "resolved":
        return "unresolved", ["ownership_or_dependency_topology_unresolved"]
    if component_lineage(source, source_context) != component_lineage(target, target_context):
        return "unresolved", ["component_lineage_differs_no_name_or_purl_based_context_merge"]
    source_content = _content(source_record)
    target_record = _record(target_coverage)
    target_content = _content(target_record)
    if target_content and source_content["state"] != target_content["state"]:
        return "conflicting", ["source_and_target_conclusions_differ_preserve_target_edits"]
    if (
        basis_source is not _NO_BASIS
        and basis_target is not _NO_BASIS
        and target_content != source_content
    ):
        if (
            source_content != basis_source
            and target_content != basis_target
            and target_content is not None
        ):
            return "conflicting", ["independent_source_and_target_assessment_edits"]
    if source_coverage["fingerprint"] != target_coverage["fingerprint"]:
        return "needs_review", ["material_context_or_source_evidence_differs"]
    approved_source = source_coverage.get("approved_assessment")
    approved_target = target_coverage.get("approved_assessment")
    if (
        _content(approved_target) == source_content
        and target_coverage.get("approved")
        and target_content == source_content
    ):
        return "already_covered", [
            "target_already_has_current_independent_coverage_for_this_content"
        ]
    if target_content is not None and target_content != source_content:
        return "needs_review", ["target_has_different_recorded_content_preserve_target_edits"]
    if (
        not source_coverage.get("approved")
        or not approved_source
        or approved_source["revision"] != source_record["revision"]
    ):
        return "needs_review", ["source_content_is_pending_or_not_currently_approved"]
    return "reusable_content", ["matching_material_inputs_content_only_new_target_review_required"]


def synchronization_preview(
    journal,
    project_id,
    source,
    target,
    basis=None,
    context_mapping=None,
    offset=0,
    limit=50,
    *,
    row_id=None,
):
    """Propose content only; knowledge ancestry never proves a software merge."""
    page([], offset, limit)
    revisions = reachable_states(journal, project_id)
    if source not in revisions or target not in revisions:
        raise ValueError("Synchronization requires committed states from one product line")
    if basis is not None and (
        basis not in _ancestors(source, revisions) or basis not in _ancestors(target, revisions)
    ):
        raise ValueError(
            "Explicit synchronization basis must be a committed ancestor of both states"
        )
    source_revision, target_revision = revisions[source], revisions[target]
    old, new = load_sections(journal, source), load_sections(journal, target)
    original = load_sections(journal, basis) if basis else None
    source_contexts = {
        item["id"]: item for key, item in old["ownership"].items() if key.startswith("context:")
    }
    target_contexts = {
        item["id"]: item for key, item in new["ownership"].items() if key.startswith("context:")
    }
    mapping = context_mapping if context_mapping is not None else {}
    if isinstance(mapping, dict) and len(mapping) > 1000:
        raise ValueError("Synchronization preview supports at most 1000 explicit context mappings")
    if not isinstance(mapping, dict) or any(
        not isinstance(key, str)
        or not isinstance(value, str)
        or key not in source_contexts
        or value not in target_contexts
        for key, value in mapping.items()
    ):
        raise ValueError(
            "Explicit context mappings must identify existing source and target contexts"
        )
    effective = [
        mapping.get(key, key) for key in source_contexts if mapping.get(key, key) in target_contexts
    ]
    if len(set(effective)) != len(effective):
        raise ValueError(
            "Synchronization cannot collapse several source contexts into one target context"
        )
    rows = []
    scopes, unknown = _scopes(old, source_revision.version)
    for source_id, identifier in scopes:
        target_id = mapping.get(source_id, source_id)
        source_context, target_context = (
            source_contexts.get(source_id),
            target_contexts.get(target_id),
        )
        source_coverage = coverage_status(
            journal, old, source_revision.version, source_id, identifier
        )
        target_coverage = coverage_status(
            journal, new, target_revision.version, target_id, identifier
        )
        source_record = _record(source_coverage)
        basis_source = basis_target = _NO_BASIS
        if original is not None:
            basis_version = revisions[basis].version
            basis_source = _content(
                _record(coverage_status(journal, original, basis_version, source_id, identifier))
            )
            basis_target = _content(
                _record(coverage_status(journal, original, basis_version, target_id, identifier))
            )
        category, reasons = _classify(
            old,
            new,
            source_context,
            target_context,
            source_record,
            source_coverage,
            target_coverage,
            basis_source,
            basis_target,
        )
        rows.append(
            {
                "id": digest(canonical([source_id, identifier, target_id])),
                "category": category,
                "vulnerability_id": identifier,
                "source_context_id": source_id,
                "target_context_id": target_id,
                "context_mapping": "explicit"
                if source_id in mapping
                else "exact_source_local_reference",
                "source": _assessment_summary(source_coverage),
                "target": _assessment_summary(target_coverage),
                "source_lineage": component_lineage(old, source_context)
                if source_context
                else None,
                "target_lineage": component_lineage(new, target_context)
                if target_context
                else None,
                "reasons": reasons,
                "requires_new_target_review": category != "already_covered",
            }
        )
    for key, record in unknown:
        rows.append(
            {
                "id": digest(canonical(["unknown_scope", key])),
                "category": "unresolved",
                "source_assessment_id": key,
                "source_assessment_revision": record.get("revision"),
                "source": record,
                "target": None,
                "reasons": ["source_assessment_has_no_explicit_version_context_scope"],
                "requires_new_target_review": True,
            }
        )
    rows.sort(
        key=lambda row: (
            row.get("source_context_id", ""),
            row.get("vulnerability_id", ""),
            row["id"],
        )
    )
    preview = {
        "format": "dtvp.synchronization-preview/1",
        "project_id": project_id,
        "source": source,
        "target": target,
        "basis": basis,
        "source_version": source_revision.version,
        "target_version": target_revision.version,
        "mode": "three_way" if basis else "two_state",
        "context_mapping": mapping,
        "apply_supported": False,
        "provenance": {
            "source": _provenance(old),
            "target": _provenance(new),
            "software_integration_verified": False,
        },
        "summary": {"by_category": dict(Counter(row["category"] for row in rows))},
        "limitations": [
            "Knowledge ancestry is not evidence of a source-code merge or fix propagation.",
            "Target inventory remains authoritative; no SBOM union, review or score copying occurs.",
            "Identity uses exact source-local references and vulnerability identifiers; aliases are not merged and mappings do not prove equivalence. Absent findings do not prove remediation; extended coverage needs independent review.",
            "No automatic synchronization is implemented. Explicit source-author draft extension requires new target review.",
        ],
    }
    preview["preview_digest"] = digest(canonical([preview, rows]))
    if row_id is not None:
        preview["selected_row"] = next((row for row in rows if row["id"] == row_id), None)
    return {**preview, **page(rows, offset, limit)}
