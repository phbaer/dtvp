"""Pinned, source-local historical comparisons; callers enforce project access."""

from collections import Counter

from dtvp.knowledge.assessments import collection_scope, semantic
from dtvp.knowledge.journal import Ref
from dtvp.knowledge.workspace import load_sections, load_workspace
from dtvp.storage import canonical, digest

MAX_OBSERVATION_ASSERTIONS = 100_000
MAX_OBSERVATION_BYTES = 32 * 1024 * 1024

LIMITATIONS = [
    "Identity uses exact source-local component/context references; names and PURLs never merge occurrences.",
    "Changed references appear as removal/addition, not a verified component migration.",
    "Missing claims/components do not prove remediation; retained assessments remain historical evidence.",
    "Historical states are read from the journal, without changing PostgreSQL or current branch heads.",
    "Attributed observation evidence remains source claims; composition, topology and human decisions are compared separately. Source-state and local-reference-only churn is excluded from evidence change counts.",
]


def page(items, offset, limit):
    if offset < 0 or not 1 <= limit <= 200:
        raise ValueError("Invalid comparison page bounds")
    return {
        "items": items[offset : offset + limit],
        "total": len(items),
        "next_offset": offset + limit if offset + limit < len(items) else None,
    }


def product_state(journal, state, project_id):
    revision = journal.state(state)
    if revision.project_id != project_id:
        raise ValueError("Historical comparison requires one product line")
    inventory = journal.records(state, "inventory")
    baseline = journal.load(inventory["baseline"]) if "baseline" in inventory else None
    if baseline is None or baseline.get("part_id") or revision.version.startswith("@"):
        raise ValueError("Revision is not a product inventory state")
    return revision


def reachable_states(journal, project_id, *, references=None):
    selected = journal.references() if references is None else references
    refs = [(Ref.model_validate_json(key), state) for key, state in selected.items()]
    pending = [
        state
        for ref, state in refs
        if ref.project_id == project_id and ref.kind in {"branch", "tag"}
    ]
    found, seen = {}, set()
    while pending:
        state = pending.pop()
        if state in seen:
            continue
        seen.add(state)
        try:
            revision = product_state(journal, state, project_id)
        except ValueError:
            # Policy, evidence and constituent parents are independently retained,
            # but are not product-version history or comparison destinations.
            continue
        found[state] = revision
        pending.extend(revision.parents)
    return found


def list_product_refs(journal, project_id, offset=0, limit=50):
    items = []
    for key, state in journal.references().items():
        ref = Ref.model_validate_json(key)
        if ref.project_id != project_id or ref.kind not in {"branch", "tag"}:
            continue
        revision = product_state(journal, state, project_id)
        items.append(
            {
                "kind": ref.kind,
                "name": ref.name,
                "state": state,
                "version": revision.version,
                "created_at": revision.created_at,
            }
        )
    return {
        "project_id": project_id,
        **page(sorted(items, key=lambda item: (item["kind"], item["name"])), offset, limit),
    }


def list_product_history(journal, project_id, version=None, offset=0, limit=50):
    revisions = reachable_states(journal, project_id)
    items = [
        {
            "state": sha,
            "version": revision.version,
            "created_at": revision.created_at,
            "actor_id": revision.actor_id,
            "reason": revision.reason,
            "parents": [parent for parent in revision.parents if parent in revisions],
        }
        for sha, revision in revisions.items()
        if version is None or revision.version == version
    ]
    items.sort(key=lambda item: (item["created_at"], item["state"]), reverse=True)
    return {"project_id": project_id, **page(items, offset, limit)}


def components(inventory):
    result = {
        item["bom-ref"]: item
        for key, item in inventory.items()
        if key.startswith(("component:", "part-root:")) and item.get("bom-ref")
    }
    root = inventory.get("root", {})
    if root.get("bom-ref"):
        result.setdefault(root["bom-ref"], root)
    return result


def component_summary(item):
    return {
        **{
            key: item[key]
            for key in ("bom-ref", "name", "group", "version", "purl", "cpe")
            if key in item
        },
        "material_digest": digest(canonical(semantic(item))),
        "record_digest": digest(canonical(item)),
    }


def dependencies(inventory):
    return {
        (edge["ref"], child)
        for edge in inventory.get("dependencies", {}).get("edges", [])
        for child in edge.get("dependsOn", [])
    }


def finding_summary(item):
    coverage, context = item["coverage"], item["context"]
    assessment = coverage.get("assessment")
    review = coverage.get("review")
    return {
        "context_id": item["context_id"],
        "vulnerability_id": item["vulnerability_id"],
        "component_ref": context["component_ref"],
        "root_ref": context["root_ref"],
        "fingerprint": coverage.get("fingerprint"),
        "status": coverage["status"],
        "ownership": {
            key: context.get(key)
            for key in (
                "team_id",
                "status",
                "candidate_teams",
                "aliases",
                "matched_rules",
                "owner_boundaries",
            )
        },
        "assessment": {key: assessment[key] for key in ("revision", "stage")}
        if assessment
        else None,
        "approved_revision": coverage.get("assessment_revision")
        if coverage.get("approved")
        else None,
        "review_digest": digest(canonical(review)) if review else None,
        "source_severity": item["source_severity"],
        "published_score": item["published_score"],
    }


def baseline_semantics(inventory):
    baseline = inventory.get("baseline", {})
    assembly = inventory.get("assembly", {})
    return {
        "kind": baseline.get("kind", "single"),
        "scope": collection_scope(baseline),
        "parts": [
            {
                "part_id": part["part_id"],
                **{key: part.get(key) for key in ("required", "role", "availability")},
                "scope": collection_scope(part.get("baseline", {})),
            }
            for part in sorted(assembly.get("parts", []), key=lambda item: item["part_id"])
        ],
        "coherence_status": assembly.get("coherence", {}).get("status"),
    }


def observation_groups(inventory):
    """Compare typed source facts independently of observation-local provenance."""
    register = inventory.get("observation_assertions")
    if register is None:
        return {}
    if (
        not isinstance(register, dict)
        or register.get("format") != "dtvp.observation-assertions/1"
        or not isinstance(register.get("components"), dict)
    ):
        raise ValueError("Unsupported observation evidence comparison register")
    groups, count, size = {}, 0, 0
    for target, assertions in register["components"].items():
        if not isinstance(target, str) or not isinstance(assertions, list):
            raise ValueError("Malformed observation evidence comparison scope")
        for assertion in assertions:
            count += 1
            if count > MAX_OBSERVATION_ASSERTIONS:
                raise ValueError("Observation evidence comparison exceeds 100000 assertions")
            if (
                not isinstance(assertion, dict)
                or not isinstance(assertion.get("component"), dict)
                or not isinstance(assertion.get("source"), str)
                or not assertion["source"]
                or assertion.get("part_id") is not None
                and not isinstance(assertion["part_id"], str)
            ):
                raise ValueError("Malformed attributed observation evidence")
            raw = canonical(assertion)
            size += len(raw)
            if size > MAX_OBSERVATION_BYTES:
                raise ValueError("Observation evidence comparison exceeds 32 MiB")
            # Only typed import-local component reference/origin is provenance.
            # Unknown component facts, source and part remain material evidence.
            facts = {
                key: value
                for key, value in assertion["component"].items()
                if key not in {"bom-ref", "dtvp_origin"}
            }
            key = (target, assertion.get("part_id"), assertion["source"])
            entry = groups.setdefault(key, {"facts": {}, "provenance": {}, "claims": {}})
            entry["facts"][canonical(facts)] = facts
            attributes = {
                key: value
                for key, value in assertion.items()
                if key not in {"source", "part_id", "state", "ref", "component"}
            }
            claim = {"component": facts, "attributes": attributes}
            entry["claims"][canonical(claim)] = claim
            provenance = {key: assertion.get(key) for key in ("state", "ref")}
            provenance["component_ref"] = assertion["component"].get("bom-ref")
            provenance["component_origin"] = assertion["component"].get("dtvp_origin")
            entry["provenance"][canonical(provenance)] = provenance
    return {
        key: {
            "component_ref": key[0],
            "part_id": key[1],
            "source": key[2],
            "facts": [entry["facts"][raw] for raw in sorted(entry["facts"])],
            "provenance": [entry["provenance"][raw] for raw in sorted(entry["provenance"])],
            "facts_digest": digest(
                canonical([entry["claims"][raw] for raw in sorted(entry["claims"])])
            ),
            "claims": [entry["claims"][raw] for raw in sorted(entry["claims"])],
        }
        for key, entry in groups.items()
    }


def observation_changes(old, new):
    left, right = observation_groups(old), observation_groups(new)
    keys = left.keys() | right.keys()
    if len(keys) > MAX_OBSERVATION_ASSERTIONS:
        raise ValueError("Observation evidence comparison exceeds 100000 scoped groups")
    rows, size, provenance_only = [], 0, 0
    for key in sorted(keys, key=canonical):
        before, after = left.get(key), right.get(key)
        if (
            before is not None
            and after is not None
            and before["facts_digest"] == after["facts_digest"]
        ):
            provenance_only += before["provenance"] != after["provenance"]
            continue
        fields = sorted(
            {
                field
                for entry in (before, after)
                if entry
                for facts in entry["facts"]
                for field in facts
            }
        )

        def values(entry, field):
            return (
                None
                if entry is None
                else sorted({canonical(facts[field]) for facts in entry["facts"] if field in facts})
            )

        changed_fields = [
            field for field in fields if values(before, field) != values(after, field)
        ]
        if (
            before is not None
            and after is not None
            and {canonical(claim["attributes"]) for claim in before["claims"]}
            != {canonical(claim["attributes"]) for claim in after["claims"]}
        ):
            changed_fields.append("source_attributes")
        change = "added" if before is None else "removed" if after is None else "changed"
        classifications = ([change] if change != "changed" else []) + ["evidence", "material"]
        if "licenses" in changed_fields:
            classifications.append("source_license")
        row = {
            "category": "observation_evidence",
            "key": list(key),
            "change": change,
            "classifications": classifications,
            "changed_fields": changed_fields,
            "before": before,
            "after": after,
        }
        size += len(canonical(row))
        if size > MAX_OBSERVATION_BYTES:
            raise ValueError("Observation evidence comparison output exceeds 32 MiB")
        rows.append(row)
    return rows, {
        "scoped_groups_before": len(left),
        "scoped_groups_after": len(right),
        "provenance_only_groups": provenance_only,
        "identity_basis": "canonical_target_reference_with_source_and_part_scope",
    }


def compare_states(journal, project_id, before, after, offset=0, limit=50):
    """One deterministic row page with full-set totals and explicit change classes."""
    page([], offset, limit)
    reachable = reachable_states(journal, project_id)
    if before not in reachable or after not in reachable:
        raise ValueError("Comparison states must be committed product history in this product line")
    # Access is checked by the API; committed membership is checked above on
    # every read. Only historical, actor-independent derived bytes are cached.
    from dtvp.knowledge.comparison_cache import cache_for, cache_key

    cache = cache_for(journal)
    key = cache_key(project_id, before, after)
    result = cache.get(key)
    if result is None:
        result = _compare_states(journal, project_id, before, after, reachable)
        cache.put(key, result)
    return {**result, **page(result["items"], offset, limit)}


def _compare_states(journal, project_id, before, after, reachable):
    """Full deterministic historical result, without authorization or presentation."""
    old, new = load_sections(journal, before), load_sections(journal, after)
    rows = []

    def add(category, key, left, right, classifications):
        if left == right:
            return
        change = "added" if left is None else "removed" if right is None else "changed"
        rows.append(
            {
                "category": category,
                "key": key,
                "change": change,
                "classifications": [change, "material"] if change != "changed" else classifications,
                "before": left,
                "after": right,
            }
        )

    left_components, right_components = components(old["inventory"]), components(new["inventory"])
    for ref in sorted(left_components.keys() | right_components.keys()):
        left, right = left_components.get(ref), right_components.get(ref)
        add(
            "component",
            ref,
            component_summary(left) if left is not None else None,
            component_summary(right) if right is not None else None,
            ["bookkeeping"] if semantic(left) == semantic(right) else ["material"],
        )
    left_edges, right_edges = dependencies(old["inventory"]), dependencies(new["inventory"])
    for edge in sorted(left_edges ^ right_edges):
        add(
            "dependency",
            list(edge),
            {"from": edge[0], "to": edge[1]} if edge in left_edges else None,
            {"from": edge[0], "to": edge[1]} if edge in right_edges else None,
            ["material"],
        )
    old_workspace = load_workspace(journal, before, paginate=False)
    new_workspace = load_workspace(journal, after, paginate=False)
    left_findings = {row["id"]: finding_summary(row) for row in old_workspace["items"]}
    right_findings = {row["id"]: finding_summary(row) for row in new_workspace["items"]}
    for key in sorted(left_findings.keys() | right_findings.keys()):
        left, right = left_findings.get(key), right_findings.get(key)
        categories = []
        if left is not None and right is not None:
            for fields, classification in (
                (["fingerprint", "source_severity"], "material"),
                (["ownership"], "ownership"),
                (["assessment", "status"], "assessment"),
                (["review_digest", "approved_revision"], "review"),
                (["published_score"], "scoring"),
            ):
                if any(left[field] != right[field] for field in fields):
                    categories.append(classification)
        add("context_finding", key, left, right, categories or ["bookkeeping"])
    left_meta = {
        "baseline": old["inventory"].get("baseline", {}),
        "assembly": old["inventory"].get("assembly"),
    }
    right_meta = {
        "baseline": new["inventory"].get("baseline", {}),
        "assembly": new["inventory"].get("assembly"),
    }
    add(
        "baseline",
        "collection",
        left_meta,
        right_meta,
        ["bookkeeping"]
        if baseline_semantics(old["inventory"]) == baseline_semantics(new["inventory"])
        else ["material"],
    )
    evidence_rows, evidence_summary = observation_changes(old["inventory"], new["inventory"])
    rows.extend(evidence_rows)
    return {
        "project_id": project_id,
        "observation_evidence": evidence_summary,
        "before": before,
        "after": after,
        "before_version": reachable[before].version,
        "after_version": reachable[after].version,
        "summary": {
            "by_category": dict(Counter(row["category"] for row in rows)),
            "by_classification": dict(
                Counter(kind for row in rows for kind in row["classifications"])
            ),
        },
        "retention": {
            label: {
                key: view["statistics"][key]
                for key in ("retained_assessments", "retained_absent_assessments")
            }
            for label, view in (("before", old_workspace), ("after", new_workspace))
        },
        "limitations": list(LIMITATIONS),
        "items": rows,
    }
