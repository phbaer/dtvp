"""Explicit selection of immutable delivery-part inputs; no identity deduplication."""

from typing import Literal

from pydantic import Field, model_validator

from dtvp.knowledge.journal import SECTIONS, Conflict, Name, Ref, Sha, Update
from dtvp.knowledge.service import component_key, part_ref
from dtvp.schemas import RequestModel
from dtvp.storage import canonical, digest


class Part(RequestModel):
    part_id: Name
    required: bool = Field(strict=True)
    state: Sha | None
    # Overlapping evidence views require reconciliation, not additive assembly.
    role: Literal["delivery"] = "delivery"


class Coherence(RequestModel):
    status: Literal["unverified", "producer_declared"] = "unverified"
    build_id: Name | None = None
    rationale: str = Field(default="", max_length=2000)

    @model_validator(mode="after")
    def declaration(self):
        if self.status == "producer_declared" and (not self.build_id or not self.rationale):
            raise ValueError("Declared build coherence needs a build ID and rationale")
        return self


class AssemblyInput(RequestModel):
    request_id: Name
    expected: Sha | None
    predecessor: Sha | None = None
    parts: list[Part] = Field(min_length=1, max_length=200)
    removed_parts: list[Name] = Field(default_factory=list, max_length=200)
    removal_reason: str = Field(default="", max_length=2000)
    withdrawn_parts: list[Name] = Field(default_factory=list, max_length=200)
    withdrawal_reason: str = Field(default="", max_length=2000)
    policy_change_reason: str = Field(default="", max_length=2000)
    coherence: Coherence = Field(default_factory=Coherence)

    @model_validator(mode="after")
    def distinct_parts(self):
        ids = [part.part_id for part in self.parts]
        if (
            len(set(ids)) != len(ids)
            or len(set(self.removed_parts)) != len(self.removed_parts)
            or len(set(self.withdrawn_parts)) != len(self.withdrawn_parts)
        ):
            raise ValueError("Part IDs and removed part IDs must be distinct")
        if set(ids) & set(self.removed_parts):
            raise ValueError("A selected part cannot also be removed")
        if self.expected and self.predecessor:
            raise ValueError("Predecessor is only allowed when creating a version")
        return self


def namespaced_ref(part_id, original):
    # Stable source-local references make part deltas useful. This is not a
    # claim of semantic identity across changed source reference schemes.
    return "part:" + digest(canonical([part_id, original]))


def selected_inventory(journal, project_id, version, part):
    current = journal.resolve(part_ref(project_id, version, part.part_id))
    seen = set()
    pending = [current] if current else []
    while pending:
        sha = pending.pop()
        if sha in seen:
            continue
        seen.add(sha)
        if sha == part.state:
            break
        pending.extend(journal.state(sha).parents)
    else:
        raise Conflict(f"Part {part.part_id} is not a committed input of this product version")
    state = journal.verify_state(part.state)
    inventory = {
        key: journal.load(value) for key, value in journal.records(part.state, "inventory").items()
    }
    baseline = inventory.get("baseline", {})
    if (
        state.project_id != project_id
        or state.version != version
        or baseline.get("part_id") != part.part_id
        or baseline.get("kind") == "assembly"
    ):
        raise Conflict("Selected input does not match its declared product/version/part")
    return inventory


def publish_assembly(journal, *, project_id, version, actor_id, data):
    operation = {
        "operation": "assembly.select/1",
        "project_id": project_id,
        "version": version,
        "actor_id": actor_id,
        **data.model_dump(mode="json"),
    }
    fingerprint = digest(canonical(operation))
    scoped_request = digest(canonical([project_id, actor_id, data.request_id]))
    with journal.writer():
        receipt = journal.receipt(scoped_request, fingerprint)
    if receipt:
        return receipt
    ref = Ref(project_id=project_id, name=version)
    if journal.resolve(ref) != data.expected:
        raise Conflict("Branch changed; reload before selecting assembly")
    parent = data.expected or data.predecessor
    sections = {name: {} for name in SECTIONS}
    if parent:
        if journal.state(parent).project_id != project_id:
            raise ValueError("Predecessor must belong to the same product line")
        sections = {
            name: {key: journal.load(sha) for key, sha in journal.records(parent, name).items()}
            for name in SECTIONS
        }
    old_manifest = sections["inventory"].get("assembly", {})
    old_parts = {part["part_id"]: part for part in old_manifest.get("parts", [])}
    new_parts = {part.part_id: part for part in data.parts}
    removed = old_parts.keys() - new_parts.keys()
    if removed != set(data.removed_parts) or (removed and not data.removal_reason):
        raise Conflict("Omitted parts require exact removed_parts and a removal reason")
    withdrawn = {
        key
        for key in old_parts.keys() & new_parts.keys()
        if old_parts[key]["state"] and not new_parts[key].state
    }
    if withdrawn != set(data.withdrawn_parts) or (withdrawn and not data.withdrawal_reason):
        raise Conflict("Deselecting inputs requires exact withdrawn_parts and a withdrawal reason")
    changed_policy = any(
        new_parts[key].required != old_parts[key]["required"]
        or new_parts[key].role != old_parts[key]["role"]
        for key in old_parts.keys() & new_parts.keys()
    )
    if changed_policy and not data.policy_change_reason:
        raise Conflict("Changing part requirements needs a policy change reason")
    inventory, findings, parts, artifacts = {}, {}, [], []
    edges, relations = [], []
    for part in sorted(data.parts, key=lambda item: item.part_id):
        selection = part.model_dump(mode="json")
        if not part.state:
            parts.append({**selection, "availability": "missing"})
            continue
        source = selected_inventory(journal, project_id, version, part)
        baseline = source["baseline"]
        parts.append({**selection, "availability": "selected", "baseline": baseline})
        artifacts.append(baseline["artifact_sha"])
        components = [value for key, value in source.items() if key.startswith("component:")]
        root = source.get("root", {})
        local_refs = {component["bom-ref"] for component in components}
        if root.get("bom-ref"):
            local_refs.add(root["bom-ref"])
            components = [root, *components]

        def qualify(original):
            if original not in local_refs:
                raise ValueError(f"Part {part.part_id} contains an unresolved local reference")
            return namespaced_ref(part.part_id, original)

        def component_view(component):
            value = {
                **component,
                "bom-ref": qualify(component["bom-ref"]),
                "dtvp_origin": {
                    "part_id": part.part_id,
                    "state": part.state,
                    "ref": component["bom-ref"],
                },
            }
            if "components" in value:
                value["components"] = [component_view(child) for child in value["components"]]
            return value

        for component in components:
            value = component_view(component)
            inventory[component_key(value["bom-ref"])] = value
        inventory["part-root:" + digest(canonical(part.part_id))] = (
            component_view(root)
            if root.get("bom-ref")
            else {"source_root": root, "part_id": part.part_id}
        )
        for edge in source.get("dependencies", {}).get("edges", []):
            edges.append(
                {
                    **edge,
                    "ref": qualify(edge["ref"]),
                    "dependsOn": [qualify(child) for child in edge.get("dependsOn", [])],
                }
            )
        for relation in source.get("relationships", {}).get("items", []):
            relations.append(
                {
                    **relation,
                    "from": qualify(relation["from"]),
                    "to": qualify(relation["to"]),
                    "part_id": part.part_id,
                }
            )
        for sha in journal.records(part.state, "vulnerabilities").values():
            item = journal.load(sha)
            value = {
                **item,
                "ref": qualify(item["ref"]),
                "dtvp_origin": {"part_id": part.part_id, "state": part.state, "ref": item["ref"]},
            }
            # Original advisory/match remain attributed payloads; normalized
            # occurrence refs point exclusively into this assembled inventory.
            value["match"] = {**item["match"], "ref": value["ref"]}
            findings[digest(canonical([part.part_id, item]))] = value
    missing = [part.part_id for part in data.parts if part.required and not part.state]
    selected_count = sum(part.state is not None for part in data.parts)
    readiness = (
        "incomplete"
        if missing or not selected_count
        else "producer_declared_ready"
        if data.coherence.status == "producer_declared"
        else "unverified"
    )
    manifest = {
        "format": "dtvp.assembly/1",
        "parts": parts,
        "coherence": data.coherence.model_dump(mode="json"),
        "coverage_verification": "not_verified",
        "readiness": readiness,
        "missing_required_parts": sorted(missing),
        "selected_part_count": selected_count,
        "removed_parts": sorted(removed),
        "removal_reason": data.removal_reason,
        "withdrawn_parts": sorted(withdrawn),
        "withdrawal_reason": data.withdrawal_reason,
        "policy_change_reason": data.policy_change_reason,
    }
    sections["inventory"] = {
        **inventory,
        "assembly": manifest,
        "baseline": {
            "kind": "assembly",
            "readiness": readiness,
            "coverage_verification": "not_verified",
        },
        "dependencies": {"edges": edges},
        "relationships": {"items": relations},
    }
    sections["vulnerabilities"] = findings
    if parent:
        sections["history"][f"inventory:{parent}"] = {"state": parent}
    # Include selected revisions as parents as well as direct original artifact
    # references: complete state/provenance remains reachable after source updates.
    parents = list(
        dict.fromkeys(([parent] if parent else []) + [p.state for p in data.parts if p.state])
    )
    state = journal.snapshot(
        project_id=project_id,
        version=version,
        actor_id=actor_id,
        reason="Select product assembly",
        sections=sections,
        parents=parents,
        artifacts=sorted(set(artifacts)),
    )
    return journal.publish(
        request_id=scoped_request,
        fingerprint=fingerprint,
        updates=[Update(ref=ref, expected=data.expected, target=state)],
    )
