"""Pinned automatic identity candidates; never rewrite occurrences or approvals."""

from collections import defaultdict

from dtvp.knowledge.comparison import page, reachable_states
from dtvp.knowledge.component_identity import reconcile_components
from dtvp.knowledge.composition import CollectionContext
from dtvp.knowledge.workspace import load_sections
from dtvp.storage import canonical, digest

MAX_COMPONENTS = 100_000


def _groups(inventory):
    groups = defaultdict(dict)
    part_roots = {
        component.get("bom-ref")
        for key, component in inventory.items()
        if key.startswith("part-root:") and component.get("bom-ref")
    }
    count = 0
    for key, component in inventory.items():
        if key == "root":
            role = "root"
        elif key.startswith("part-root:"):
            role = "part-root"
        elif key.startswith("component:"):
            if component.get("bom-ref") in part_roots:
                continue
            role = "component"
        else:
            continue
        ref = component.get("bom-ref")
        if not ref:
            continue
        count += 1
        if count > MAX_COMPONENTS:
            raise ValueError("Identity comparison exceeds the component bound")
        part = component.get("dtvp_origin", {}).get("part_id") or inventory.get("baseline", {}).get(
            "part_id"
        )
        groups[(part, role)][ref] = component
    return groups


def _boundary(inventory, part_id):
    baseline = inventory.get("baseline", {})
    if part_id is not None:
        part = next(
            (
                part
                for part in inventory.get("assembly", {}).get("parts", [])
                if part["part_id"] == part_id
            ),
            None,
        )
        if part is None:
            return None
        baseline = part.get("baseline", {})
    return CollectionContext.model_validate(baseline.get("collection", {})).boundary()


def identity_matches(journal, project_id, source, target, *, offset=0, limit=50):
    page([], offset, limit)
    committed = reachable_states(journal, project_id)
    if source not in committed or target not in committed:
        raise ValueError("Identity matching requires committed product history")
    old, new = (load_sections(journal, sha)["inventory"] for sha in (source, target))
    left, right = _groups(old), _groups(new)
    baseline_compatible = _boundary(old, None) == _boundary(new, None)
    scope_compatible = baseline_compatible
    rows, diagnostics, matched, unresolved = [], [], 0, 0
    for scope, components in sorted(right.items(), key=lambda pair: canonical(pair[0])):
        if not baseline_compatible or _boundary(old, scope[0]) != _boundary(new, scope[0]):
            scope_compatible = False
            unresolved += len(components)
            for ref in sorted(components):
                if len(diagnostics) < 100:
                    diagnostics.append({"current_ref": ref, "reason": "collection_scope_changed"})
            continue
        result = reconcile_components(left.get(scope, {}), components)
        for pair in result["pairs"]:
            matched += 1
            rows.append(
                {
                    "kind": "component",
                    "source_id": pair["previous_ref"],
                    "target_id": pair["current_ref"],
                    "basis": pair["basis"],
                    "scope": {"part_id": scope[0], "role": scope[1]},
                }
            )
        unresolved += len(components) - len(result["pairs"])
        diagnostics.extend(result["unresolved"][: 100 - len(diagnostics)])
    rows.sort(key=lambda row: (row["target_id"], row["source_id"]))
    summary = {
        "matched": matched,
        "unresolved": unresolved,
        "source_occurrences": sum(map(len, left.values())),
        "target_occurrences": sum(map(len, right.values())),
        "scope_compatible": scope_compatible,
    }
    report = {
        "format": "dtvp.identity-matches/1",
        "policy": "dtvp.component-identity/1",
        "project_id": project_id,
        "source": source,
        "target": target,
        "summary": summary,
        "unresolved": diagnostics,
        "diagnostics_truncated": unresolved > len(diagnostics),
        "limitations": [
            "Matches are unique compatible package/artifact candidates within a part and occurrence role.",
            "No inventory, stable identity registry, context, assessment, approval or score is changed.",
            "Matching component coordinates do not prove consuming-context or applicability equivalence.",
            "Missing/ambiguous identity remains unresolved; descriptive names never establish identity alone.",
        ],
    }
    return {
        **report,
        "report_digest": digest(canonical([report, rows])),
        **page(rows, offset, limit),
    }
