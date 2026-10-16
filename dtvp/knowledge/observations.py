"""Explicit nonauthoritative SBOM layers and pinned reconciled graph publication."""

from copy import deepcopy
from typing import Literal

from pydantic import Field, model_validator

from dtvp.knowledge.assembly import namespaced_ref
from dtvp.knowledge.comparison import reachable_states
from dtvp.knowledge.component_identity import reconcile_components
from dtvp.knowledge.component_lineages import reconcile_lineages
from dtvp.knowledge.composition import CollectionContext
from dtvp.knowledge.journal import SECTIONS, Conflict, Name, Ref, Sha, Update
from dtvp.knowledge.observation_graph import propose_observation
from dtvp.knowledge.pipeline_config import config_ref, current_config, validate_source_role
from dtvp.knowledge.pipeline_metadata import SubjectDeclaration
from dtvp.knowledge.service import component_key, inventory_sections, validate_time
from dtvp.knowledge.workspace import load_sections
from dtvp.parsers import parse
from dtvp.schemas import RequestModel
from dtvp.storage import canonical, digest

MAX_CANDIDATE_BYTES = 64 * 1024 * 1024
MAX_REPORT_BYTES = 64 * 1024 * 1024
MAX_RECORDS = 100_000


def _bound_candidate(sections):
    from dtvp.knowledge.component_lineages import MAX_IDENTITIES, MAX_LEDGER_BYTES

    inventory = sections["inventory"]
    ledger = inventory.get("identity", {})
    if (
        len(ledger.get("entries", {})) + len(ledger.get("tombstones", {})) > MAX_IDENTITIES
        or len(canonical(ledger)) > MAX_LEDGER_BYTES
    ):
        raise ValueError("Observation identity ledger exceeds its retained bound")
    if (
        sum(key == "root" or key.startswith(("component:", "part-root:")) for key in inventory)
        > MAX_RECORDS
        or len(inventory.get("dependencies", {}).get("edges", [])) > MAX_RECORDS
        or len(inventory.get("relationships", {}).get("items", [])) > MAX_RECORDS
        or len(sections["vulnerabilities"]) > MAX_RECORDS
        or len(canonical(sections)) > MAX_CANDIDATE_BYTES
    ):
        raise ValueError("Observation candidate exceeds record or 64 MiB bounds")


class ObservationMetadata(RequestModel):
    request_id: Name
    source: Name
    expected: Sha | None
    expected_authority: Sha
    expected_configuration: Sha | None
    part_id: Name | None = None
    build_number: int = Field(ge=0, strict=True)
    occurred_at: str
    context: CollectionContext = Field(default_factory=CollectionContext)
    subject_declaration: SubjectDeclaration | None = None


class ObservationInput(ObservationMetadata):
    sbom: dict


class AdoptedRelationship(RequestModel):
    from_: str = Field(alias="from", min_length=1, max_length=4096)
    to: str = Field(min_length=1, max_length=4096)
    kind: Literal["DEPENDS_ON", "CONTAINS"]


class SelectedObservation(RequestModel):
    source: Name
    part_id: Name | None = None
    state: Sha
    accepted_components: list[str] = Field(default_factory=list, max_length=2000)
    accepted_relationships: list[AdoptedRelationship] = Field(default_factory=list, max_length=2000)
    reason: str = Field(default="", max_length=6000)

    @model_validator(mode="after")
    def meaningful(self):
        if len(set(self.accepted_components)) != len(self.accepted_components):
            raise ValueError("Adopted observation components must be distinct")
        edges = [
            canonical(item.model_dump(mode="json", by_alias=True))
            for item in self.accepted_relationships
        ]
        if len(set(edges)) != len(edges):
            raise ValueError("Adopted observation relationships must be distinct")
        if (self.accepted_components or self.accepted_relationships) and not self.reason.strip():
            raise ValueError("Inventory/topology adoption requires an explicit reason")
        return self


class ObservationSelection(RequestModel):
    request_id: Name
    expected: Sha
    expected_configuration: Sha | None
    sources: list[SelectedObservation] = Field(default_factory=list, max_length=200)
    removal_reason: str = Field(default="", max_length=6000)
    preview_digest: Sha | None = None

    @model_validator(mode="after")
    def unique(self):
        keys = [(item.part_id, item.source) for item in self.sources]
        if len(keys) != len(set(keys)):
            raise ValueError("Selected observation source bindings must be distinct")
        return self


def observation_ref(project_id, version, part_id, source):
    return Ref(
        kind="source",
        project_id=project_id,
        name="observation:" + digest(canonical([version, part_id, source])),
    )


def source_key(part_id, source):
    return digest(canonical([part_id, source]))


def _current(journal, project_id, version, expected, expected_configuration):
    if journal.resolve(Ref(project_id=project_id, name=version)) != expected:
        raise Conflict("Product version changed; retain pins and prepare a new observation request")
    if expected not in reachable_states(journal, project_id):
        raise ValueError("Observation target must be committed product history")
    if journal.state(expected).version != version:
        raise ValueError("Observation target belongs to another product version")
    configuration, config = current_config(journal, project_id)
    if configuration != expected_configuration:
        raise Conflict("Pipeline configuration changed")
    sections = load_sections(journal, expected)
    if sections["inventory"].get("baseline", {}).get("withdrawn"):
        raise Conflict("Withdrawn inventory cannot receive observation imports or selections")
    return sections, config if configuration else None


def _base(journal, project_id, version, expected, sections):
    selected = sections["inventory"].get("observations", {}).get("authority_state", expected)
    if (
        selected not in reachable_states(journal, project_id)
        or journal.state(selected).version != version
    ):
        raise ValueError("Observation authority base is not retained product history")
    return selected, load_sections(journal, selected)


def authority_inventory(journal, sections, part_id):
    inventory = sections["inventory"]
    if inventory.get("baseline", {}).get("kind") != "assembly":
        if part_id is not None:
            raise ValueError("A single baseline has no selected delivery-part ID")
        return inventory
    part = next(
        (part for part in inventory["assembly"]["parts"] if part["part_id"] == part_id), None
    )
    if part is None or not part.get("state"):
        raise ValueError("Observation requires an available selected delivery part")
    return load_sections(journal, part["state"])["inventory"]


def _prepare(journal, project_id, version, source, actor_id, data, raw):
    operation = [
        "observation.import/1",
        project_id,
        version,
        source,
        actor_id,
        data.model_dump(mode="json"),
        digest(raw),
    ]
    request_id, fingerprint = (
        digest(canonical([project_id, actor_id, data.request_id])),
        digest(canonical(operation)),
    )
    with journal.writer():
        receipt = journal.receipt(request_id, fingerprint)
    return request_id, fingerprint, receipt


def import_observation(journal, *, project_id, version, source, actor_id, data, raw=None):
    if source != data.source:
        raise ValueError("Observation source differs from its declared binding")
    raw = canonical(data.sbom) if raw is None and isinstance(data, ObservationInput) else raw
    if raw is None:
        raise ValueError("Observation requires original SBOM bytes or an SBOM object")
    if len(raw) > 32 * 1024 * 1024:
        raise ValueError("Observation SBOM exceeds 32 MiB")
    request_id, fingerprint, receipt = _prepare(
        journal, project_id, version, source, actor_id, data, raw
    )
    if receipt:
        return receipt
    sections, configuration = _current(
        journal, project_id, version, data.expected_authority, data.expected_configuration
    )
    _, base = _base(journal, project_id, version, data.expected_authority, sections)
    authority = authority_inventory(journal, base, data.part_id)
    validate_source_role(configuration, data.part_id, authority["baseline"]["source"], "authority")
    validate_source_role(configuration, data.part_id, source, "observation")
    ref = observation_ref(project_id, version, data.part_id, source)
    if journal.resolve(ref) != data.expected:
        raise Conflict("Observation source changed")
    if data.subject_declaration is not None and (
        data.subject_declaration.product_id != project_id
        or data.subject_declaration.version != version
    ):
        raise ValueError("Subject declaration does not match the authorized product/version")
    previous = (
        load_sections(journal, data.expected) if data.expected else {name: {} for name in SECTIONS}
    )
    old = previous["inventory"]
    if old and data.build_number <= old["baseline"]["build_number"]:
        raise Conflict("Observation build is not newer than its source binding")
    document = parse(raw)
    normalized, claims = inventory_sections(
        document,
        artifact_sha=digest(raw),
        source=source,
        build_number=data.build_number,
        occurred_at=validate_time(data.occurred_at),
        collection=data.context,
        representation="original_bytes",
        version=version,
        part_id=data.part_id,
    )
    normalized["baseline"].update(role="observation", product_version=version)
    report = propose_observation(
        authority, normalized, subject_declaration=data.subject_declaration
    )
    if report["status"] == "blocked":
        raise ValueError("Observation binding unresolved: " + ", ".join(report["blocked_reasons"]))
    normalized["identity"] = reconcile_lineages(
        old,
        normalized,
        project_id=project_id,
        version=version,
        previous_state=data.expected,
        previous_version=version if data.expected else None,
    )
    raw_sha, report_sha = journal.objects.put(raw), journal.store(report)
    metadata = {
        "format": "dtvp.observation-import/1",
        "project_id": project_id,
        "version": version,
        "source": source,
        "part_id": data.part_id,
        "actor_id": actor_id,
        "authority_state": data.expected_authority,
        "configuration": data.expected_configuration,
        "subject_declaration": data.subject_declaration.model_dump(mode="json")
        if data.subject_declaration
        else None,
        "report_sha256": report_sha,
    }
    candidate = {name: {} for name in SECTIONS}
    candidate.update(
        inventory=normalized, vulnerabilities=claims, history={"observation-import": metadata}
    )
    parents = list(
        dict.fromkeys(
            [
                data.expected_authority,
                *([data.expected] if data.expected else []),
                *([data.expected_configuration] if data.expected_configuration else []),
            ]
        )
    )
    state = journal.snapshot(
        project_id=project_id,
        version="@observation",
        actor_id=actor_id,
        reason="Import nonauthoritative SBOM observation",
        sections=candidate,
        parents=parents,
        artifacts=sorted(
            {
                raw_sha,
                report_sha,
                *[sha for parent in parents for sha in journal.state(parent).artifacts],
            }
        ),
    )
    return journal.publish(
        request_id=request_id,
        fingerprint=fingerprint,
        updates=[Update(ref=ref, expected=data.expected, target=state)],
        checks=[
            (Ref(project_id=project_id, name=version), data.expected_authority),
            (config_ref(project_id), data.expected_configuration),
        ],
    )


def _retained_source(journal, project_id, version, selection):
    current = journal.resolve(
        observation_ref(project_id, version, selection.part_id, selection.source)
    )
    seen, pending = set(), [current] if current else []
    while pending:
        state = pending.pop()
        if state in seen:
            continue
        seen.add(state)
        if len(seen) > 10000:
            raise ValueError("Observation source history exceeds its bound")
        if state == selection.state:
            break
        revision = journal.state(state)
        if revision.version == "@observation":
            pending.extend(revision.parents)
    else:
        raise ValueError("Observation selection is not retained in its source binding")
    sections = load_sections(journal, selection.state)
    metadata = sections["history"].get("observation-import", {})
    if journal.state(selection.state).project_id != project_id or any(
        metadata.get(key) != value
        for key, value in {
            "project_id": project_id,
            "version": version,
            "source": selection.source,
            "part_id": selection.part_id,
        }.items()
    ):
        raise ValueError("Observation source scope differs from its selection")
    return sections, metadata


def _translate_claim(value, mapping, source, origin):
    claim = deepcopy(value)
    claim["ref"] = mapping[value["ref"]]
    claim["source"] = "observation:" + source
    claim["match"] = {**claim.get("match", {}), "ref": claim["ref"]}
    # Preserve original advisory refs as source assertions, not live graph endpoints.
    claim["dtvp_origin"] = origin
    return claim


def _placement(component):
    locations = {
        key: component[key]
        for key in ("install_location", "install_path", "location", "instance_id", "instance")
        if key in component
    }
    occurrences = component.get("evidence", {}).get("occurrences", [])
    if occurrences:
        locations["occurrence_locations"] = sorted({item["location"] for item in occurrences})
    return canonical(locations)


def _adoption_matches(inventory, source_inventory, components, unresolved, selection):
    """Only unique strong identities with identical part/role/installation scope."""
    source_root = source_inventory.get("root", {}).get("bom-ref")
    groups = {}
    for local in unresolved:
        component = components[local]
        groups.setdefault(
            ("root" if local == source_root else "component", _placement(component)), {}
        )[local] = component
    matches = {}
    for (role, placement), candidates in groups.items():
        existing = {}
        for key, component in inventory.items():
            if not key.startswith("component:"):
                continue
            origin = component.get("dtvp_origin", {})
            if (
                origin.get("part_id") != selection.part_id
                or origin.get("source") in (None, selection.source)
                or origin.get("role", "component") != role
                or _placement(component) != placement
            ):
                continue
            existing[component["bom-ref"]] = component
        for pair in reconcile_components(existing, candidates)["pairs"]:
            matches[pair["current_ref"]] = pair["previous_ref"]
    return matches


def build_selection(journal, *, project_id, version, data):
    sections, configuration = _current(
        journal, project_id, version, data.expected, data.expected_configuration
    )
    authority_state, base = _base(journal, project_id, version, data.expected, sections)
    base_inventory = base["inventory"]
    if base_inventory.get("baseline", {}).get("kind") == "assembly":
        for part in base_inventory["assembly"]["parts"]:
            if part.get("state"):
                authority = authority_inventory(journal, base, part["part_id"])
                validate_source_role(
                    configuration, part["part_id"], authority["baseline"]["source"], "authority"
                )
    else:
        validate_source_role(configuration, None, base_inventory["baseline"]["source"], "authority")
    previous = sections["inventory"].get("observations", {}).get("sources", {})
    selected_keys = {source_key(item.part_id, item.source) for item in data.sources}
    if previous.keys() - selected_keys and not data.removal_reason.strip():
        raise ValueError("Observation removal requires an explicit reason")
    for item in data.sources:
        earlier = previous.get(source_key(item.part_id, item.source), {})
        old_components = set(earlier.get("accepted_components", []))
        new_components = set(item.accepted_components)
        old_edges = {canonical(edge) for edge in earlier.get("accepted_relationships", [])}
        new_edges = {
            canonical(edge.model_dump(mode="json", by_alias=True))
            for edge in item.accepted_relationships
        }
        if (old_components - new_components or old_edges - new_edges) and not (
            item.reason.strip() or data.removal_reason.strip()
        ):
            raise ValueError(
                "Removing adopted observation inventory/topology requires an explicit reason"
            )
    sections["inventory"], sections["vulnerabilities"] = (
        deepcopy(base["inventory"]),
        deepcopy(base["vulnerabilities"]),
    )
    if "identity" not in sections["inventory"]:
        from dtvp.knowledge.assembly_lineages import assemble_lineages
        from dtvp.knowledge.component_lineages import reconcile_lineages

        if base_inventory.get("baseline", {}).get("kind") == "assembly":
            sections["inventory"]["identity"] = assemble_lineages(
                [
                    (
                        part["part_id"],
                        part["state"],
                        load_sections(journal, part["state"])["inventory"],
                    )
                    for part in base_inventory["assembly"]["parts"]
                    if part.get("state")
                ],
                project_id=project_id,
                version=version,
                qualify=namespaced_ref,
            )
        else:
            sections["inventory"]["identity"] = reconcile_lineages(
                {}, sections["inventory"], project_id=project_id, version=version
            )
    output, reports, parents, artifacts = (
        {},
        [],
        [data.expected, authority_state],
        set(journal.state(data.expected).artifacts),
    )
    input_bytes = 0
    report_bytes = 0
    for selection in sorted(data.sources, key=lambda item: canonical([item.part_id, item.source])):
        source, metadata = _retained_source(journal, project_id, version, selection)
        input_bytes += len(canonical(source["inventory"])) + len(
            canonical(source["vulnerabilities"])
        )
        if input_bytes > 64 * 1024 * 1024:
            raise ValueError("Selected observations exceed the 64 MiB normalized input bound")
        authority = authority_inventory(journal, base, selection.part_id)
        validate_source_role(
            configuration, selection.part_id, authority["baseline"]["source"], "authority"
        )
        validate_source_role(configuration, selection.part_id, selection.source, "observation")
        report = propose_observation(
            authority, source["inventory"], subject_declaration=metadata.get("subject_declaration")
        )
        if report["status"] == "blocked":
            raise Conflict(
                "Selected observation no longer matches current authority: "
                + ", ".join(report["blocked_reasons"])
            )
        qualify = (
            (lambda ref: namespaced_ref(selection.part_id, ref))
            if selection.part_id
            else (lambda ref: ref)
        )
        mapping = {
            item["observation_ref"]: qualify(item["authority_ref"]) for item in report["mapping"]
        }
        components = {
            item["bom-ref"]: item
            for key, item in source["inventory"].items()
            if key == "root" or key.startswith("component:")
        }
        unresolved = {item["observation_ref"] for item in report["component_proposals"]}
        if not set(selection.accepted_components) <= unresolved:
            raise ValueError("Adoption must select existing unresolved observation occurrences")
        adopted_matches = _adoption_matches(
            sections["inventory"], source["inventory"], components, unresolved, selection
        )
        for local in selection.accepted_components:
            item = deepcopy(components[local])
            entry = source["inventory"]["identity"]["entries"][local]
            target = "observation:" + digest(
                canonical([selection.part_id, selection.source, entry["lineage_id"]])
            )
            mapping[local] = target
            item.pop("components", None)
            item["bom-ref"] = target
            item["dtvp_origin"] = {
                "state": selection.state,
                "ref": local,
                "part_id": selection.part_id,
                "source": selection.source,
                "role": "root"
                if source["inventory"].get("root", {}).get("bom-ref") == local
                else "component",
            }
            if local in adopted_matches:
                target = adopted_matches[local]
                mapping[local] = target
                retained = sections["inventory"][component_key(target)]
                supports = retained.setdefault(
                    "dtvp_observations", [deepcopy(retained["dtvp_origin"])]
                )
                supports.append(item["dtvp_origin"])
                conflicts = set(retained.get("dtvp_observation_conflicts", []))
                ignored = {
                    "bom-ref",
                    "dtvp_origin",
                    "dtvp_observations",
                    "dtvp_observation_conflicts",
                }
                conflicts.update(
                    key
                    for key in set(retained) | set(item)
                    if key not in ignored and retained.get(key) != item.get(key)
                )
                if conflicts:
                    retained["dtvp_observation_conflicts"] = sorted(conflicts)
                continue
            sections["inventory"][component_key(target)] = item
            sections["inventory"].setdefault("identity", {}).setdefault("entries", {})[target] = {
                **deepcopy(entry),
                "role": "component",
                "source": {
                    **item["dtvp_origin"],
                    "artifact_sha": source["inventory"]["baseline"]["artifact_sha"],
                },
            }
        proposed = {
            (item["observation"]["from"], item["observation"]["to"], item["observation"]["kind"])
            for item in report["topology_proposals"]
        }
        for edge in selection.accepted_relationships:
            if (
                (edge.from_, edge.to, edge.kind) not in proposed
                or edge.from_ not in mapping
                or edge.to not in mapping
            ):
                raise ValueError(
                    "Adopted topology must select proposed edges with mapped/adopted endpoints"
                )
            relationship = {
                "from": mapping[edge.from_],
                "to": mapping[edge.to],
                "kind": edge.kind,
                "origin": "observation",
                "source": selection.source,
                "part_id": selection.part_id,
            }
            values = sections["inventory"]["relationships"]["items"]
            if not any(
                (item["from"], item["to"], item["kind"])
                == (relationship["from"], relationship["to"], edge.kind)
                for item in values
            ):
                values.append(relationship)
            if edge.kind == "DEPENDS_ON":
                edges = sections["inventory"]["dependencies"]["edges"]
                parent = next((item for item in edges if item["ref"] == relationship["from"]), None)
                if parent is None:
                    edges.append({"ref": relationship["from"], "dependsOn": [relationship["to"]]})
                elif relationship["to"] not in parent.get("dependsOn", []):
                    parent["dependsOn"] = sorted([*parent.get("dependsOn", []), relationship["to"]])
        assertions = sections["inventory"].setdefault(
            "observation_assertions", {"format": "dtvp.observation-assertions/1", "components": {}}
        )["components"]
        for local, target in sorted(mapping.items()):
            assertions.setdefault(target, []).append(
                {
                    "source": selection.source,
                    "part_id": selection.part_id,
                    "state": selection.state,
                    "ref": local,
                    "component": deepcopy(components[local]),
                }
            )
        for key, claim in source["vulnerabilities"].items():
            if claim.get("ref") in mapping:
                origin = {
                    "state": selection.state,
                    "ref": claim["ref"],
                    "part_id": selection.part_id,
                    "source": selection.source,
                }
                sections["vulnerabilities"][
                    "observation:" + digest(canonical([selection.state, key]))
                ] = _translate_claim(claim, mapping, selection.source, origin)
        report_bytes += len(canonical(report))
        if report_bytes > MAX_REPORT_BYTES:
            raise ValueError("Selected observation reports exceed 64 MiB")
        _bound_candidate(sections)
        reports.append(
            {
                "source": selection.source,
                "part_id": selection.part_id,
                "state": selection.state,
                "report": report,
            }
        )
        output[source_key(selection.part_id, selection.source)] = selection.model_dump(
            mode="json", by_alias=True
        )
        parents.append(selection.state)
        artifacts.update(journal.state(selection.state).artifacts)
    sections["inventory"]["observations"] = {
        "format": "dtvp.observation-selection/1",
        "authority_state": authority_state,
        "configuration": data.expected_configuration,
        "sources": output,
        "removal_reason": data.removal_reason,
    }
    if data.expected_configuration:
        sections["inventory"]["pipeline_configuration"] = {
            "state": data.expected_configuration,
            "configuration": configuration,
        }
        parents.append(data.expected_configuration)
    from dtvp.knowledge.evidence import apply_current_evidence, evidence_ref
    from dtvp.knowledge.ownership import current_policy, policy_ref, resolve_ownership

    _bound_candidate(sections)
    policy, config = current_policy(journal, project_id)
    resolve_ownership(sections, version=version, policy_state=policy, config=config)
    evidence = apply_current_evidence(journal, sections, project_id)
    if policy:
        parents.append(policy)
    if evidence:
        parents.append(evidence)
    preview = {
        "format": "dtvp.observation-publication-preview/1",
        "project_id": project_id,
        "version": version,
        "expected": data.expected,
        "configuration": data.expected_configuration,
        "authority_state": authority_state,
        "sources": output,
        "reports": reports,
        "ownership_policy": policy,
        "evidence": evidence,
        "inventory_digest": digest(canonical(sections["inventory"])),
        "claims_digest": digest(canonical(sections["vulnerabilities"])),
        "human_decisions_changed": False,
    }
    _bound_candidate(sections)
    if len(canonical(preview)) > MAX_REPORT_BYTES:
        raise ValueError("Observation publication preview exceeds 64 MiB")
    preview["preview_digest"] = digest(canonical(preview))
    return {
        "sections": sections,
        "parents": list(dict.fromkeys(parents)),
        "artifacts": sorted(artifacts),
        "preview": preview,
        "checks": [
            (config_ref(project_id), data.expected_configuration),
            (policy_ref(project_id), policy),
            (evidence_ref(project_id), evidence),
        ],
    }


def publish_selection(journal, *, project_id, version, actor_id, data):
    request_id = digest(canonical([project_id, actor_id, data.request_id]))
    fingerprint = digest(
        canonical(
            [
                "observation.select/1",
                project_id,
                version,
                actor_id,
                data.model_dump(mode="json", by_alias=True),
            ]
        )
    )
    with journal.writer():
        receipt = journal.receipt(request_id, fingerprint)
    if receipt:
        return receipt
    candidate = build_selection(journal, project_id=project_id, version=version, data=data)
    if data.preview_digest != candidate["preview"]["preview_digest"]:
        raise Conflict("Observation publication preview changed")
    state = journal.snapshot(
        project_id=project_id,
        version=version,
        actor_id=actor_id,
        reason="Publish selected SBOM observations",
        sections=candidate["sections"],
        parents=candidate["parents"],
        artifacts=candidate["artifacts"],
    )
    return journal.publish(
        request_id=request_id,
        fingerprint=fingerprint,
        updates=[
            Update(
                ref=Ref(project_id=project_id, name=version), expected=data.expected, target=state
            )
        ],
        checks=candidate["checks"],
    )
