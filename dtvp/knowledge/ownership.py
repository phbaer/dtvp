"""Versioned responsibility, separate from access and assessment validity."""

from pydantic import Field, model_validator

from dtvp.knowledge.journal import SECTIONS, Conflict, Name, Ref, Sha, Update
from dtvp.knowledge.selectors import component_identity, find_team_mapping_match
from dtvp.schemas import RequestModel
from dtvp.storage import canonical, digest

MAX_CONTEXTS = 100_000


def check_context_count(count):
    if count > MAX_CONTEXTS:
        raise ValueError(
            "Consuming-context limit exceeded; reconcile product/root scope explicitly"
        )


class Rule(RequestModel):
    selector: Name
    team_id: Name
    aliases: list[Name] = Field(default_factory=list, max_length=50)
    versions: list[Name] | None = Field(default=None, min_length=1, max_length=200)


class OwnershipInput(RequestModel):
    request_id: Name
    expected_policy: Sha | None
    expected_versions: dict[Name, Sha]
    rules: list[Rule] = Field(default_factory=list, max_length=1000)
    context_roots: dict[Name, list[Name]] = Field(default_factory=dict)

    @model_validator(mode="after")
    def unambiguous_rules(self):
        grouped = {}
        for rule in self.rules:
            for prior in grouped.get(rule.selector, []):
                if (
                    prior.versions is None
                    or rule.versions is None
                    or set(prior.versions) & set(rule.versions)
                ):
                    raise ValueError(
                        "Duplicate selectors must have disjoint product-version scopes"
                    )
            grouped.setdefault(rule.selector, []).append(rule)
        for roots in self.context_roots.values():
            if not roots or len(roots) != len(set(roots)):
                raise ValueError("Explicit consuming roots must be nonempty and distinct")
        return self


def policy_ref(project_id):
    return Ref(kind="policy", project_id=project_id, name="ownership")


def current_policy(journal, project_id):
    state = journal.resolve(policy_ref(project_id))
    config = (
        journal.load(journal.records(state, "ownership")["configuration"])
        if state
        else {"rules": [], "context_roots": {}}
    )
    return state, config


def product_heads(refs, project_id):
    return {
        ref.name: sha
        for key, sha in refs.items()
        if (ref := Ref.model_validate_json(key)).project_id == project_id and ref.kind == "branch"
    }


def reachable(graph, start):
    seen, pending = set(), [start]
    while pending:
        node = pending.pop()
        if node in seen:
            continue
        seen.add(node)
        pending.extend(graph[node] - seen)
    return seen


def source_roots(graph):
    """Condensation roots, retaining rootless cycles without enumerating paths."""
    seen, order = set(), []
    for start in sorted(graph):
        pending = [(start, False)]
        while pending:
            node, finished = pending.pop()
            if finished:
                order.append(node)
            elif node not in seen:
                seen.add(node)
                pending.append((node, True))
                pending.extend((child, False) for child in sorted(graph[node], reverse=True))
    reverse = {node: set() for node in graph}
    for parent, children in graph.items():
        for child in children:
            reverse[child].add(parent)
    groups, membership = [], {}
    for start in reversed(order):
        if start in membership:
            continue
        index = len(groups)
        members, pending = set(), [start]
        while pending:
            node = pending.pop()
            if node in membership:
                continue
            membership[node] = index
            members.add(node)
            pending.extend(reverse[node])
        groups.append(members)
    parents = [set() for _ in groups]
    for parent, children in graph.items():
        for child in children:
            if membership[parent] != membership[child]:
                parents[membership[child]].add(membership[parent])
    return (
        [
            (min(group), len(group) > 1 or min(group) in graph[min(group)])
            for index, group in enumerate(groups)
            if not parents[index]
        ],
        reverse,
        membership,
        parents,
    )


def boundary_masks(matches, membership, parents):
    """Propagate owner reachability/shadowing once across the condensation DAG.

    Kosaraju assigns SCCs in source-to-sink order. Owner boundaries in one SCC
    cannot strictly shadow each other; any boundary in a later SCC shadows every
    upstream owner, including an ancestor reached through a bypass edge.
    """
    boundaries = sorted(matches)
    bits = {ref: 1 << index for index, ref in enumerate(boundaries)}
    own = [0] * len(parents)
    for ref, bit in bits.items():
        own[membership[ref]] |= bit
    upstream, shadowed = [], []
    for index, previous in enumerate(parents):
        inherited, hidden = 0, 0
        for parent in previous:
            inherited |= upstream[parent]
            hidden |= shadowed[parent]
        upstream.append(own[index] | inherited)
        shadowed.append(hidden | inherited if own[index] else hidden)
    return boundaries, bits, upstream, shadowed


def selected_boundaries(mask, boundaries):
    """Decode only surviving bits, avoiding scans over every configured owner."""
    result = []
    while mask:
        bit = mask & -mask
        result.append(boundaries[bit.bit_length() - 1])
        mask ^= bit
    return result


def resolve_ownership(sections, *, version, policy_state=None, config=None):
    config = config or {"rules": [], "context_roots": {}}
    rules = [
        rule
        for rule in config["rules"]
        if rule.get("versions") is None or version in rule["versions"]
    ]
    mapping = {rule["selector"]: [rule["team_id"], *rule.get("aliases", [])] for rule in rules}
    inventory = sections["inventory"]
    baseline = inventory.get("baseline", {})
    part_graphs = {
        part["part_id"]: part.get("baseline", {}).get("dependency_graph", "not_reported")
        for part in inventory.get("assembly", {}).get("parts", [])
    }
    components = {
        value["bom-ref"]: value for key, value in inventory.items() if key.startswith("component:")
    }
    root = inventory.get("root", {})
    if root.get("bom-ref"):
        components.setdefault(root["bom-ref"], root)
    graph = {ref: set() for ref in components}
    for edge in inventory.get("dependencies", {}).get("edges", []):
        if edge["ref"] not in graph or any(
            child not in graph for child in edge.get("dependsOn", [])
        ):
            raise ValueError("Ownership graph has unresolved dependency references")
        graph[edge["ref"]].update(edge.get("dependsOn", []))
    condensed, reverse, membership, parents = source_roots(graph)
    explicit_roots = config.get("context_roots", {}).get(version)
    declared = {root["bom-ref"]} if root.get("bom-ref") else set()
    declared.update(
        value["bom-ref"]
        for key, value in inventory.items()
        if key.startswith("part-root:") and value.get("bom-ref")
    )
    if explicit_roots is not None:
        if any(ref not in graph for ref in explicit_roots):
            raise Conflict("A configured consuming root is absent; update roots explicitly")
        roots = {ref: "configured" for ref in explicit_roots}
    else:
        roots = {ref: "declared" for ref in declared}
    root_subjects, covered, context_count = {}, set(), 0
    for ref in roots:
        subjects = reachable(graph, ref)
        context_count += len(subjects)
        check_context_count(context_count)
        root_subjects[ref] = subjects
        covered.update(subjects)
    # Configured roots do not hide disconnected data; residual trees/cycles stay
    # visible as inferred contexts requiring topology confirmation.
    for ref, cycle in sorted(condensed):
        if ref not in covered:
            descendants_of_root = reachable(graph, ref)
            if explicit_roots and descendants_of_root & set(explicit_roots):
                # An explicitly excluded aggregate above configured consuming
                # roots is not another consuming context. Report its scope below.
                continue
            roots[ref] = "cycle_without_declared_root" if cycle else "inferred"
            context_count += len(descendants_of_root)
            check_context_count(context_count)
            root_subjects[ref] = descendants_of_root
            covered.update(root_subjects[ref])
    matches = {
        ref: match
        for ref, component in components.items()
        if (match := find_team_mapping_match(mapping, component_identity(component)))
    }
    boundaries, boundary_bits, upstream, shadowed = boundary_masks(matches, membership, parents)
    contexts = {}
    for root_ref, root_basis in sorted(roots.items()):
        subjects = root_subjects[root_ref]
        root_owner_bits = 0
        for boundary in subjects & matches.keys():
            root_owner_bits |= boundary_bits[boundary]
        root_match = matches.get(root_ref) or find_team_mapping_match(
            mapping, component_identity(components[root_ref]), include_wildcard=True
        )
        for ref in sorted(subjects):
            # A mapped descendant shadows its ancestor even with a bypass path.
            # Mutually reachable boundaries are retained, exposing cyclic conflict.
            group = membership[ref]
            effective = selected_boundaries(
                upstream[group] & root_owner_bits & ~shadowed[group], boundaries
            )
            selected = [matches[boundary] for boundary in effective]
            fallback = None
            if not selected:
                fallback = find_team_mapping_match(
                    mapping, component_identity(components[ref]), include_wildcard=True
                )
                if fallback:
                    selected = [fallback]
            teams = sorted({match.tags[0] for match in selected})
            status = "conflict" if len(teams) > 1 else "resolved" if teams else "unassigned"
            graph_status = (
                part_graphs.get(
                    components[ref].get("dtvp_origin", {}).get("part_id"), "not_reported"
                )
                if baseline.get("kind") == "assembly"
                else baseline.get("dependency_graph", "not_reported")
            )
            if root_basis == "cycle_without_declared_root" or graph_status != "reported":
                status = "topology_unknown"
            context_id = digest(canonical([root_ref, ref]))
            contexts["context:" + context_id] = {
                "id": context_id,
                "root_ref": root_ref,
                "component_ref": ref,
                "team_id": teams[0] if len(teams) == 1 else None,
                "team_scope": {team: True for team in teams},
                "root_team_id": root_match.tags[0] if root_match else None,
                "candidate_teams": teams,
                "status": status,
                "root_basis": root_basis,
                "dependency_graph": graph_status,
                "owner_boundaries": effective,
                "matched_rules": sorted({match.key for match in selected}),
                "aliases": sorted({tag for match in selected for tag in match.tags[1:]}),
                "delegated": bool(effective and effective != [root_ref] and ref != root_ref),
                "assignment": "fallback"
                if fallback
                else "explicit"
                if ref in effective
                else "inherited"
                if effective
                else "unassigned",
                "incoming_refs": sorted(reverse[ref] & subjects),
                "identity_basis": "source_local_refs",
                "coverage_verification": "not_verified",
                "component_fingerprint": digest(canonical(components[ref])),
            }
    sections["ownership"] = {
        "policy": {"state": policy_state, **config},
        "summary": {
            "roots": roots,
            "contexts": len(contexts),
            "path_representation": "dependency_graph",
            "identity_basis": "source_local_refs",
            "outside_selected_roots": sorted(graph.keys() - covered),
            "topology_status": (
                "reported"
                if all(value == "reported" for value in part_graphs.values())
                else "partially_reported"
                if any(value == "reported" for value in part_graphs.values())
                else "not_reported"
            )
            if baseline.get("kind") == "assembly"
            else baseline.get("dependency_graph", "not_reported"),
        },
        **contexts,
    }


def update_policy(journal, *, project_id, actor_id, data):
    fingerprint = digest(
        canonical(["ownership.configure/1", project_id, actor_id, data.model_dump(mode="json")])
    )
    request_id = digest(canonical([project_id, actor_id, data.request_id]))
    with journal.writer():
        receipt = journal.receipt(request_id, fingerprint)
    if receipt:
        return receipt
    refs = journal.references()
    if (
        refs.get(policy_ref(project_id).key) != data.expected_policy
        or product_heads(refs, project_id) != data.expected_versions
    ):
        raise Conflict("Ownership or product versions changed; reload before configuring")
    if set(data.context_roots) - data.expected_versions.keys():
        raise ValueError("Explicit roots must name an existing product version")
    config = data.model_dump(mode="json", include={"rules", "context_roots"})
    sections = {name: {} for name in SECTIONS}
    sections["ownership"] = {"configuration": config}
    policy = journal.snapshot(
        project_id=project_id,
        version="@ownership",
        actor_id=actor_id,
        reason="Configure component ownership",
        sections=sections,
        parents=[data.expected_policy] if data.expected_policy else [],
    )
    updates = [Update(ref=policy_ref(project_id), expected=data.expected_policy, target=policy)]
    for version, parent in sorted(data.expected_versions.items()):
        state = journal.state(parent)
        sections = {
            name: {key: journal.load(sha) for key, sha in journal.records(parent, name).items()}
            for name in SECTIONS
        }
        resolve_ownership(sections, version=version, policy_state=policy, config=config)
        target = journal.snapshot(
            project_id=project_id,
            version=version,
            actor_id=actor_id,
            reason="Resolve component ownership",
            sections=sections,
            parents=[parent, policy],
            artifacts=state.artifacts,
        )
        updates.append(
            Update(ref=Ref(project_id=project_id, name=version), expected=parent, target=target)
        )
    return journal.publish(
        request_id=request_id,
        fingerprint=fingerprint,
        updates=updates,
        branch_heads={project_id: data.expected_versions},
    )
