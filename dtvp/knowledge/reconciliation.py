"""Human-attributed occurrence correspondence; never identity merges or approval transfer."""

import re
from datetime import UTC, datetime
from typing import Literal

from packageurl import PackageURL
from pydantic import Field, field_validator

from dtvp.knowledge.assessments import semantic
from dtvp.knowledge.comparison import page, product_state, reachable_states
from dtvp.knowledge.journal import Conflict, Name, Ref, Sha, Update
from dtvp.knowledge.workspace import load_sections
from dtvp.schemas import RequestModel
from dtvp.storage import canonical, digest

FORMAT = "dtvp.correspondence/1"
LIMITATIONS = [
    "Correspondence is an attributed human assertion between exact source occurrences, not verified identity or artifact equivalence.",
    "Component correspondence and consuming-context correspondence are separate; no transitive closure, merge or split is inferred.",
    "Assessments, approvals, ownership, metadata, CPE mappings, VEX and published scores are never transferred or rewritten.",
]


class Pair(RequestModel):
    kind: Literal["component", "context"]
    source_id: str = Field(min_length=1, max_length=4096, pattern=r"^[^\x00-\x1f\x7f]+$")
    target_id: str = Field(min_length=1, max_length=4096, pattern=r"^[^\x00-\x1f\x7f]+$")


class ReconciliationInput(RequestModel):
    request_id: Name
    expected: Sha
    expected_revision: Sha | None
    source: Sha
    preview_digest: Sha
    pairs: list[Pair] = Field(min_length=1, max_length=100)
    rationale: str = Field(min_length=1, max_length=6000)
    evidence: list[dict] = Field(default_factory=list, max_length=100)

    @field_validator("rationale")
    @classmethod
    def meaningful(cls, value):
        if not value.strip():
            raise ValueError("Correspondence requires a meaningful human rationale")
        return value


class RetractionInput(RequestModel):
    request_id: Name
    expected: Sha
    expected_revision: Sha
    reason: str = Field(min_length=1, max_length=6000)

    @field_validator("reason")
    @classmethod
    def meaningful(cls, value):
        if not value.strip():
            raise ValueError("Retraction requires a meaningful human reason")
        return value


def correspondence_key(reconciliation_id):
    return "reconciliation:" + digest(canonical(reconciliation_id))


def _facts(component):
    if component is None:
        return None
    return {
        key: component[key]
        for key in ("bom-ref", "type", "name", "group", "version", "purl", "hashes")
        if key in component
    }


def _family(component):
    purl = component.get("purl")
    if not purl:
        return None
    if not isinstance(purl, str):
        raise ValueError("Invalid package URL")
    value = PackageURL.from_string(purl)
    return PackageURL(
        type=value.type,
        namespace=value.namespace,
        name=value.name,
        qualifiers=value.qualifiers,
        subpath=value.subpath,
    ).to_string()


def _version(component):
    declared = component.get("version")
    coordinate = (
        PackageURL.from_string(component["purl"]).version if component.get("purl") else None
    )
    return declared or coordinate, bool(declared and coordinate and declared != coordinate)


HASH_LENGTHS = {
    "MD5": 32,
    "SHA-1": 40,
    "SHA-224": 56,
    "SHA-256": 64,
    "SHA-384": 96,
    "SHA-512": 128,
    "SHA3-256": 64,
    "SHA3-384": 96,
    "SHA3-512": 128,
    "BLAKE2B-256": 64,
    "BLAKE2B-384": 96,
    "BLAKE2B-512": 128,
    "BLAKE3": 64,
}
HASH_ALIASES = {
    alias: algorithm
    for algorithm in HASH_LENGTHS
    for alias in (algorithm, algorithm.replace("-", ""))
}


def _hashes(component):
    entries = component.get("hashes", [])
    if not isinstance(entries, list):
        raise ValueError("invalid_component_hash_evidence")
    result = {}
    for item in entries:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("alg"), str)
            or not isinstance(item.get("content"), str)
        ):
            raise ValueError("invalid_component_hash_evidence")
        algorithm = HASH_ALIASES.get(item["alg"].upper())
        if algorithm is None:
            raise ValueError("unsupported_component_hash_algorithm")
        content = item["content"]
        if not re.fullmatch("[0-9a-fA-F]{" + str(HASH_LENGTHS[algorithm]) + "}", content):
            raise ValueError("invalid_component_hash_evidence")
        result.setdefault(algorithm, set()).add(content.lower())
    return result


def _comparison(source, target):
    if source is None or target is None:
        return {"classification": "unresolved", "blocked": True, "reasons": ["occurrence_missing"]}
    try:
        left, right = _family(source), _family(target)
        source_version, source_conflict = _version(source)
        target_version, target_conflict = _version(target)
    except ValueError:
        return {
            "classification": "conflicting",
            "blocked": True,
            "reasons": ["invalid_package_url"],
        }
    if source_conflict or target_conflict:
        return {
            "classification": "conflicting",
            "blocked": True,
            "reasons": ["component_version_coordinate_conflict"],
        }
    reasons = []
    if left and right and left != right:
        return {
            "classification": "conflicting",
            "blocked": True,
            "reasons": ["package_family_conflict"],
        }

    try:
        old, new = _hashes(source), _hashes(target)
    except ValueError as error:
        return {"classification": "unresolved", "blocked": True, "reasons": [str(error)]}
    hash_conflicts = sorted(key for key in old.keys() & new.keys() if old[key] != new[key])
    same_version = source_version == target_version
    if hash_conflicts and same_version:
        return {
            "classification": "conflicting",
            "blocked": True,
            "reasons": ["same_version_hash_conflict"],
            "hash_conflicts": hash_conflicts,
        }
    if not same_version:
        reasons.append("package_version_changed")
    if hash_conflicts:
        reasons.append("artifact_hashes_changed_across_versions")
    if not left or not right:
        reasons.append("package_coordinates_missing_no_verified_identity")
    if not old or not new:
        reasons.append("artifact_hash_evidence_missing")
    return {
        "classification": "material_change" if not same_version else "candidate",
        "blocked": False,
        "reasons": reasons or ["reported_coordinates_and_hashes_compatible_not_identity_proof"],
    }


def _occurrence_index(sections):
    inventory = sections["inventory"]
    components = {
        item["bom-ref"]: item
        for key, item in inventory.items()
        if (key == "root" or key.startswith(("component:", "part-root:"))) and item.get("bom-ref")
    }
    graph = {
        edge["ref"]: set(edge.get("dependsOn", []))
        for edge in inventory.get("dependencies", {}).get("edges", [])
    }
    return {"components": components, "graph": graph, "usage": {}}


def _usage(root_ref, index):
    cache, graph = index["usage"], index["graph"]
    if root_ref not in cache:
        seen, pending = set(), [root_ref]
        while pending:
            ref = pending.pop()
            if ref in seen:
                continue
            seen.add(ref)
            pending.extend(graph.get(ref, set()) - seen)
        edges = [[ref, sorted(graph.get(ref, set()))] for ref in sorted(seen)]
        components = [[ref, semantic(index["components"].get(ref))] for ref in sorted(seen)]
        cache[root_ref] = {
            "fingerprint": digest(canonical([components, edges])),
            "components": len(seen),
            "dependency_edges": sum(len(graph.get(ref, ())) for ref in seen),
        }
    return cache[root_ref]


def _occurrence(sections, kind, identifier, usage_cache):
    if kind == "component":
        return {"component": _facts(usage_cache["components"].get(identifier))}
    context = sections["ownership"].get("context:" + identifier)
    if not context:
        return {"context": None, "component": None, "root": None}
    return {
        "context": semantic(context),
        "component": _facts(usage_cache["components"].get(context["component_ref"])),
        "root": _facts(usage_cache["components"].get(context["root_ref"])),
        "usage": _usage(context["root_ref"], usage_cache),
    }


def preview_reconciliation(journal, project_id, source, target, pairs):
    pairs = [value if isinstance(value, Pair) else Pair.model_validate(value) for value in pairs]
    if not 1 <= len(pairs) <= 100:
        raise ValueError("Correspondence preview requires 1 to 100 explicit pairs")
    for direction in ("source_id", "target_id"):
        values = {(pair.kind, getattr(pair, direction)) for pair in pairs}
        if len(values) != len(pairs):
            raise ValueError("Correspondence pairs must be one-to-one within each relation kind")
    references = journal.references()
    previous = product_state(journal, source, project_id)
    current = product_state(journal, target, project_id)
    if source not in reachable_states(journal, project_id, references=references):
        raise ValueError("Correspondence source must be committed product history")
    if references.get(Ref(project_id=project_id, name=current.version).key) != target:
        raise Conflict("Correspondence target version changed; reload current baseline")
    source_sections, target_sections = (
        load_sections(journal, source),
        load_sections(journal, target),
    )
    rows = []
    source_usage, target_usage = (
        _occurrence_index(source_sections),
        _occurrence_index(target_sections),
    )
    for pair in sorted(pairs, key=lambda value: (value.kind, value.source_id, value.target_id)):
        old = _occurrence(source_sections, pair.kind, pair.source_id, source_usage)
        new = _occurrence(target_sections, pair.kind, pair.target_id, target_usage)
        result = _comparison(old["component"], new["component"])
        if pair.kind == "context":
            root = _comparison(old["root"], new["root"])
            result["root_comparison"] = root
            if root["blocked"]:
                result.update(
                    classification="conflicting"
                    if root["classification"] == "conflicting"
                    else "unresolved",
                    blocked=True,
                )
                result["reasons"] += ["consuming_root_" + reason for reason in root["reasons"]]
            elif canonical([old["context"], old.get("usage")]) != canonical(
                [new["context"], new.get("usage")]
            ):
                result["reasons"].append("consuming_context_changed_requires_new_target_review")
        rows.append({**pair.model_dump(), **result, "source_facts": old, "target_facts": new})
    content = {
        "format": "dtvp.correspondence-preview/1",
        "project_id": project_id,
        "source": source,
        "target": target,
        "source_version": previous.version,
        "target_version": current.version,
        "items": rows,
        "eligible": not any(row["blocked"] for row in rows),
    }
    return {
        **content,
        "preview_digest": digest(canonical(content)),
        "limitations": list(LIMITATIONS),
    }


def _prepare(journal, project_id, version, actor_id, reconciliation_id, data, operation):
    fingerprint = digest(
        canonical(
            [
                "correspondence." + operation,
                project_id,
                version,
                actor_id,
                reconciliation_id,
                data.model_dump(mode="json"),
            ]
        )
    )
    request_id = digest(canonical([project_id, actor_id, data.request_id]))
    with journal.writer():
        receipt = journal.receipt(request_id, fingerprint)
    if receipt:
        return receipt, None, None, request_id, fingerprint
    ref = Ref(project_id=project_id, name=version)
    if journal.resolve(ref) != data.expected:
        raise Conflict("Correspondence target version changed")
    previous = product_state(journal, data.expected, project_id)
    if previous.version != version:
        raise ValueError("Correspondence requires the selected target version")
    sections = load_sections(journal, data.expected)
    record = sections["history"].get(correspondence_key(reconciliation_id))
    if (record["revision"] if record else None) != data.expected_revision:
        raise Conflict("Correspondence assertion revision changed")
    if record and journal.load(record["revision"]) != record["payload"]:
        raise ValueError("Correspondence differs from its immutable revision")
    return None, sections, previous, request_id, fingerprint


def _publish(
    journal,
    project_id,
    version,
    actor_id,
    reconciliation_id,
    data,
    payload,
    sections,
    previous,
    request_id,
    fingerprint,
):
    revision = journal.store(payload)
    sections["history"][correspondence_key(reconciliation_id)] = {
        "format": FORMAT,
        "revision": revision,
        "payload": payload,
    }
    state = journal.snapshot(
        project_id=project_id,
        version=version,
        actor_id=actor_id,
        reason="Record explicit occurrence correspondence",
        sections=sections,
        parents=list(dict.fromkeys([data.expected, payload["source"]])),
        artifacts=sorted(
            set(previous.artifacts) | set(journal.state(payload["source"]).artifacts) | {revision}
        ),
    )
    return journal.publish(
        request_id=request_id,
        fingerprint=fingerprint,
        updates=[
            Update(
                ref=Ref(project_id=project_id, name=version), expected=data.expected, target=state
            )
        ],
    )


def confirm_reconciliation(
    journal, project_id, version, actor_id, reconciliation_id, data, authorize
):
    authorize("write")
    receipt, sections, previous, request_id, fingerprint = _prepare(
        journal, project_id, version, actor_id, reconciliation_id, data, "confirm"
    )
    if receipt:
        return receipt
    preview = preview_reconciliation(journal, project_id, data.source, data.expected, data.pairs)
    if preview["preview_digest"] != data.preview_digest:
        raise Conflict("Correspondence preview changed; review it again")
    if not preview["eligible"]:
        raise Conflict("Conflicting or missing occurrences cannot be confirmed as corresponding")
    payload = {
        "format": FORMAT,
        "reconciliation_id": reconciliation_id,
        "project_id": project_id,
        "version": version,
        "actor_id": actor_id,
        "created_at": datetime.now(UTC).isoformat(),
        "previous": data.expected_revision,
        "stage": "active",
        "source": data.source,
        "target": data.expected,
        "preview": preview,
        "rationale": data.rationale,
        "evidence": data.evidence,
    }
    return _publish(
        journal,
        project_id,
        version,
        actor_id,
        reconciliation_id,
        data,
        payload,
        sections,
        previous,
        request_id,
        fingerprint,
    )


def retract_reconciliation(
    journal, project_id, version, actor_id, reconciliation_id, data, authorize
):
    authorize("write")
    receipt, sections, previous, request_id, fingerprint = _prepare(
        journal, project_id, version, actor_id, reconciliation_id, data, "retract"
    )
    if receipt:
        return receipt
    record = sections["history"][correspondence_key(reconciliation_id)]
    old = record["payload"]
    if old["version"] != version or old["stage"] != "active":
        raise Conflict("Retraction requires an active assertion in this exact target version")
    payload = {
        **old,
        "actor_id": actor_id,
        "created_at": datetime.now(UTC).isoformat(),
        "previous": data.expected_revision,
        "stage": "retracted",
        "retraction_reason": data.reason,
    }
    return _publish(
        journal,
        project_id,
        version,
        actor_id,
        reconciliation_id,
        data,
        payload,
        sections,
        previous,
        request_id,
        fingerprint,
    )


def list_reconciliations(journal, state, offset=0, limit=50):
    node = journal.state(state)
    product_state(journal, state, node.project_id)
    sections = load_sections(journal, state)
    items = []
    for key, record in sorted(sections["history"].items()):
        if not key.startswith("reconciliation:"):
            continue
        if journal.load(record["revision"]) != record["payload"]:
            raise ValueError("Correspondence differs from its immutable revision")
        items.append({**record, "in_version_scope": record["payload"]["version"] == node.version})
    return {**page(items, offset, limit), "limitations": list(LIMITATIONS)}
