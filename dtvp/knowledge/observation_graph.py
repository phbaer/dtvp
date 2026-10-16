"""Pure same-subject enrichment preview; inventory authority is never replaced."""

from collections import defaultdict
from copy import deepcopy

from dtvp.knowledge.component_identity import reconcile_components
from dtvp.knowledge.composition import CollectionContext
from dtvp.storage import canonical, digest

MAX_ENTRIES = 100_000
MAX_DIAGNOSTICS = 200
MAX_INPUT_BYTES = 32 * 1024 * 1024
MAX_REPORT_BYTES = 64 * 1024 * 1024


def _finish(report):
    if (
        sum(
            len(report[key])
            for key in (
                "mapping",
                "supplemental_assertions",
                "edge_support",
                "component_proposals",
                "topology_proposals",
                "diagnostics",
            )
        )
        > MAX_ENTRIES
    ):
        raise ValueError("Observation reconciliation exceeds output record bound")
    raw = canonical(report)
    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError("Observation reconciliation exceeds report byte bound")
    return {**report, "report_digest": digest(raw)}


def _bounded(value):
    pending, nodes, size = [(value, 0)], 0, 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if nodes > 1_000_000 or depth > 64:
            raise ValueError("Observation reconciliation exceeds structural bounds")
        if isinstance(item, str):
            size += len(item.encode())
        elif isinstance(item, dict):
            if any(not isinstance(key, str) for key in item):
                raise ValueError("Observation inventory requires string document keys")
            pending.extend((key, depth + 1) for key in item)
            pending.extend((value, depth + 1) for value in item.values())
        elif isinstance(item, list):
            pending.extend((value, depth + 1) for value in item)
        elif item is not None and not isinstance(item, (int, float, bool)):
            raise ValueError("Observation inventory requires JSON values")
        if size > MAX_INPUT_BYTES:
            raise ValueError("Observation reconciliation exceeds input byte bound")
    canonical(value)  # Reject non-finite numbers before deriving any candidates.


def _components(inventory):
    groups, refs = defaultdict(dict), {}
    baseline = inventory.get("baseline", {})
    root = inventory.get("root", {})
    if not isinstance(root, dict):
        raise ValueError("Invalid observation root component")
    for key, component in inventory.items():
        if key != "root" and not key.startswith("component:"):
            continue
        if not isinstance(component, dict):
            raise ValueError("Invalid observation component")
        ref = component.get("bom-ref")
        if not ref:
            continue
        if not isinstance(ref, str):
            raise ValueError("Invalid observation component reference")
        if key != "root" and root.get("bom-ref") == ref:
            if component != root:
                raise ValueError("Contradictory duplicate root occurrence")
            continue
        if ref in refs:
            raise ValueError("Duplicate observation occurrence reference")
        role = "root" if key == "root" else "component"
        origin = component.get("dtvp_origin", {})
        if not isinstance(origin, dict):
            raise ValueError("Invalid observation occurrence origin")
        part = origin.get("part_id", baseline.get("part_id"))
        if part != baseline.get("part_id"):
            raise ValueError("Observation occurrence crosses delivery parts")
        # Explicit installation evidence cannot be treated as a wildcard.
        locations = {
            field: component[field]
            for field in ("install_location", "install_path", "location", "instance_id", "instance")
            if field in component
        }
        evidence = component.get("evidence", {})
        if not isinstance(evidence, dict):
            raise ValueError("Invalid observation component evidence")
        occurrences = evidence.get("occurrences", [])
        if not isinstance(occurrences, list):
            raise ValueError("Invalid observation occurrence locations")
        if occurrences:
            if any(
                not isinstance(item, dict) or not isinstance(item.get("location"), str)
                for item in occurrences
            ):
                raise ValueError("Invalid observation occurrence locations")
            locations["occurrence_locations"] = sorted({item["location"] for item in occurrences})
        groups[(role, canonical(locations))][ref] = component
        refs[ref] = component
    return groups, refs


def _edges(inventory):
    edges = defaultdict(list)
    relationships = inventory.get("relationships", {})
    dependencies = inventory.get("dependencies", {})
    if not isinstance(relationships, dict) or not isinstance(dependencies, dict):
        raise ValueError("Invalid observation relationship documents")
    relationships, dependencies = relationships.get("items", []), dependencies.get("edges", [])
    if not isinstance(relationships, list) or not isinstance(dependencies, list):
        raise ValueError("Invalid observation relationships")
    for index, relation in enumerate(relationships):
        if not isinstance(relation, dict) or any(
            not isinstance(relation.get(key), str) or not relation[key]
            for key in ("from", "to", "kind")
        ):
            raise ValueError("Invalid typed observation relationship")
        edges[(relation["from"], relation["to"], relation["kind"])].append(
            {
                "representation": "relationships",
                "index": index,
                **({"origin": relation["origin"]} if "origin" in relation else {}),
            }
        )
        if len(edges) > MAX_ENTRIES:
            raise ValueError("Observation reconciliation exceeds edge bound")
    for index, relation in enumerate(dependencies):
        if (
            not isinstance(relation, dict)
            or not isinstance(relation.get("ref"), str)
            or (not isinstance(relation.get("dependsOn", []), list))
        ):
            raise ValueError("Invalid observation dependencies")
        for child in relation.get("dependsOn", []):
            if not isinstance(child, str) or not child:
                raise ValueError("Invalid observation dependency reference")
            edges[(relation["ref"], child, "DEPENDS_ON")].append(
                {
                    "representation": "dependencies",
                    "index": index,
                }
            )
            if len(edges) > MAX_ENTRIES:
                raise ValueError("Observation reconciliation exceeds edge bound")
    return edges


def propose_observation(authority_inventory, observation_inventory):
    """Return attributed candidates only; caller pins product/version/source states.

    Inputs must represent one explicit part, not assembled overlapping scopes.
    Same producer-declared artifact digest is required, not proof of authenticity.
    Reports never insert components, change topology, or extend human coverage.
    """
    _bounded([authority_inventory, observation_inventory])
    if not isinstance(authority_inventory, dict) or not isinstance(observation_inventory, dict):
        raise ValueError("Observation reconciliation requires inventory documents")
    baselines = [
        inventory.get("baseline", {}) for inventory in (authority_inventory, observation_inventory)
    ]
    if any(not isinstance(item, dict) for item in baselines):
        raise ValueError("Invalid observation baseline")
    contexts = [CollectionContext.model_validate(item.get("collection", {})) for item in baselines]
    blocked = []
    if any(item.get("kind") == "assembly" for item in baselines):
        blocked.append("individual_delivery_part_required")
    if baselines[0].get("part_id") != baselines[1].get("part_id"):
        blocked.append("delivery_part_changed")
    if any(context.subject_digest is None for context in contexts):
        blocked.append("subject_digest_unknown")
    elif contexts[0].subject_digest != contexts[1].subject_digest:
        blocked.append("subject_digest_changed")
    if contexts[0].boundary() != contexts[1].boundary():
        blocked.append("collection_scope_changed")
    report = {
        "format": "dtvp.observation-graph/1",
        "policy": "dtvp.component-identity/1",
        "status": "blocked" if blocked else "proposals_only",
        "blocked_reasons": blocked,
        "input_digests": [
            digest(canonical(item)) for item in (authority_inventory, observation_inventory)
        ],
        "mapping": [],
        "supplemental_assertions": [],
        "edge_support": [],
        "component_proposals": [],
        "topology_proposals": [],
        "diagnostics": [],
        "summary": {},
        "diagnostics_truncated": False,
        "limitations": [
            "Authority inventory remains unchanged; observations cannot add or remove inventory implicitly.",
            "Subject binding is producer-declared, not verification of delivered artifact or completeness.",
            "Component correspondence never merges consuming contexts or transfers assessments/approvals.",
            "Missing observation edges do not propose deletion of authoritative topology.",
        ],
    }
    if blocked:
        return _finish(report)
    left, authority = _components(authority_inventory)
    right, observed = _components(observation_inventory)
    authority_edges, observation_edges = _edges(authority_inventory), _edges(observation_inventory)
    if any(a not in authority or b not in authority for a, b, _ in authority_edges):
        raise ValueError("Authority topology contains unresolved component endpoints")
    if sum(map(len, (authority, observed, authority_edges, observation_edges))) > MAX_ENTRIES:
        raise ValueError("Observation reconciliation exceeds combined occurrence/edge bound")
    mapping, unresolved = {}, 0
    for scope, components in sorted(right.items()):
        result = reconcile_components(left.get(scope, {}), components)
        for pair in result["pairs"]:
            source, target = pair["current_ref"], pair["previous_ref"]
            mapping[source] = target
            report["mapping"].append(
                {
                    "observation_ref": source,
                    "authority_ref": target,
                    "basis": pair["basis"],
                    "role": scope[0],
                }
            )
        unresolved += result["summary"]["unresolved"]
        report["diagnostics"].extend(
            result["unresolved"][: MAX_DIAGNOSTICS - len(report["diagnostics"])]
        )
    for source in sorted(observed):
        if source not in mapping:
            report["component_proposals"].append(
                {"observation_ref": source, "reason": "unresolved_occurrence_identity"}
            )
            continue
        target = mapping[source]
        for field, value in sorted(observed[source].items()):
            if field in {"bom-ref", "components", "dtvp_origin"} or value is None:
                continue
            baseline = authority[target].get(field)
            if baseline is not None and canonical(value) == canonical(baseline):
                continue
            report["supplemental_assertions"].append(
                {
                    "observation_ref": source,
                    "authority_ref": target,
                    "field": field,
                    "status": "conflict" if baseline is not None else "additional_information",
                    "observation_value": deepcopy(value),
                    **({"authority_value": deepcopy(baseline)} if baseline is not None else {}),
                }
            )
            if len(report["supplemental_assertions"]) > MAX_ENTRIES:
                raise ValueError("Observation reconciliation exceeds assertion bound")
    pairs = defaultdict(set)
    for a, b, kind in authority_edges:
        pairs[(a, b)].add(kind)
    supported = set()
    for (a, b, kind), provenance in sorted(observation_edges.items()):
        translated = (mapping.get(a), mapping.get(b), kind)
        entry = {
            "observation": {"from": a, "to": b, "kind": kind},
            "observation_support": provenance,
        }
        if translated in authority_edges:
            supported.add(translated)
            report["edge_support"].append(
                {
                    **entry,
                    "authority": dict(zip(("from", "to", "kind"), translated, strict=True)),
                    "authority_support": authority_edges[translated],
                }
            )
        else:
            reason = (
                "unresolved_endpoint"
                if None in translated[:2]
                else (
                    "relationship_kind_differs" if pairs[translated[:2]] else "additional_topology"
                )
            )
            report["topology_proposals"].append(
                {
                    **entry,
                    "reason": reason,
                    "proposed_authority_endpoints": {"from": translated[0], "to": translated[1]},
                }
            )
    report["mapping"].sort(key=lambda item: item["observation_ref"])
    report["summary"] = {
        "authority_occurrences": len(authority),
        "observation_occurrences": len(observed),
        "matched_occurrences": len(mapping),
        "unresolved_occurrences": unresolved,
        "supplemental_assertions": len(report["supplemental_assertions"]),
        "field_conflicts": sum(
            item["status"] == "conflict" for item in report["supplemental_assertions"]
        ),
        "authority_typed_edges": len(authority_edges),
        "observation_typed_edges": len(observation_edges),
        "supported_authority_edges": len(supported),
        "authority_edges_without_observation_support": len(authority_edges) - len(supported),
        "topology_proposals": len(report["topology_proposals"]),
    }
    report["diagnostics_truncated"] = unresolved > len(report["diagnostics"])
    return _finish(report)
