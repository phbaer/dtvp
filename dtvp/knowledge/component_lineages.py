"""Additive occurrence lineage ledger; never assessment or graph equivalence.

Only unique strong-marker matches within one import binding continue a lineage.
Source-local references, component payloads and assessment fingerprints stay exact.
"""

import re
from copy import deepcopy
from itertools import chain

from dtvp.knowledge.component_identity import reconcile_components
from dtvp.knowledge.composition import CollectionContext
from dtvp.storage import canonical, digest

FORMAT = "dtvp.component-lineages/1"
POLICY = "dtvp.component-identity/1"
MAX_IDENTITIES = 100_000
MAX_LEDGER_BYTES = 32 * 1024 * 1024


def _validate_prior(prior, groups):
    entries, retired = prior.get("entries"), prior.get("tombstones")
    if not isinstance(entries, dict) or not isinstance(retired, dict):
        raise ValueError("Malformed component lineage ledger")
    if len(entries) + len(retired) > MAX_IDENTITIES or len(canonical(prior)) > MAX_LEDGER_BYTES:
        raise ValueError("Retained component lineage ledger exceeds its bound")
    roles = {ref: role for role, components in groups.items() for ref in components}
    if set(entries) != set(roles):
        raise ValueError("Component lineage entries disagree with retained inventory")
    ids = set()
    for is_retired, key, item in chain(
        ((False, key, item) for key, item in entries.items()),
        ((True, key, item) for key, item in retired.items()),
    ):
        if (
            not isinstance(item, dict)
            or any(
                not isinstance(item.get(field), str) or not item[field]
                for field in ("lineage_id", "first_artifact", "first_ref", "role")
            )
            or any(
                not re.fullmatch("[a-f0-9]{64}", item[field])
                for field in ("lineage_id", "first_artifact")
            )
        ):
            raise ValueError("Malformed retained component lineage identity")
        identity = item["lineage_id"]
        if identity in ids or item["role"] not in ("root", "component"):
            raise ValueError("Duplicate or invalid retained component lineage identity")
        ids.add(identity)
        if not is_retired:
            if item["role"] != roles[key]:
                raise ValueError("Component lineage occurrence role changed")
        elif key != identity or any(
            not isinstance(item.get(field), str) or not item[field]
            for field in ("last_ref", "last_state", "last_artifact")
        ):
            raise ValueError("Malformed retained component lineage tombstone")


def _components(inventory):
    groups = {"root": {}, "component": {}}
    root_ref = inventory.get("root", {}).get("bom-ref")
    for key, component in inventory.items():
        role = "root" if key == "root" else "component" if key.startswith("component:") else None
        if role == "component" and component.get("bom-ref") == root_ref:
            continue
        if role and component.get("bom-ref"):
            groups[role][component["bom-ref"]] = component
    if sum(map(len, groups.values())) > MAX_IDENTITIES:
        raise ValueError("Component lineage inventory exceeds its occurrence bound")
    return groups


def _scope(inventory, project_id, version):
    baseline = inventory.get("baseline", {})
    return {
        "project_id": project_id,
        "version": version,
        "part_id": baseline.get("part_id"),
        "source": baseline.get("source"),
        "boundary": list(
            CollectionContext.model_validate(baseline.get("collection", {})).boundary()
        ),
    }


def _initial(scope, artifact, role, ref):
    return {
        "lineage_id": digest(canonical([FORMAT, scope, artifact, role, ref])),
        "first_artifact": artifact,
        "first_ref": ref,
        "role": role,
    }


def reconcile_lineages(
    previous,
    current,
    *,
    project_id,
    version,
    previous_state=None,
    previous_version=None,
    explicit_predecessor=False,
):
    """Return bounded metadata for this accepted import, without mutating inputs.

    Historical pre-ledger states bootstrap deterministically from their original
    artifact/ref. Tombstones record disappearance, not remediation. Returning
    packages are not silently matched against absent historical occurrences.
    """
    scope = _scope(current, project_id, version)
    previous_scope = _scope(previous, project_id, previous_version)
    compatible = (
        bool(previous_state)
        and (previous_version == version or explicit_predecessor)
        and all(previous_scope[key] == scope[key] for key in scope if key != "version")
    )
    old_groups = _components(previous) if compatible else {"root": {}, "component": {}}
    groups = _components(current)
    prior = previous.get("identity") if compatible else None
    if prior is not None and (
        not isinstance(prior, dict)
        or prior.get("format") != FORMAT
        or prior.get("policy") != POLICY
        or prior.get("scope") != previous_scope
    ):
        raise ValueError("Unsupported or inconsistent component lineage ledger")
    if prior:
        _validate_prior(prior, old_groups)
    old_entries = prior["entries"] if prior else {}
    tombstones = deepcopy(prior.get("tombstones", {})) if prior else {}
    entries, continued = {}, set()
    assigned = set()
    artifact = current["baseline"]["artifact_sha"]
    previous_artifact = previous.get("baseline", {}).get("artifact_sha")
    for role, components in groups.items():
        result = reconcile_components(old_groups[role], components)
        pairs = {pair["current_ref"]: pair for pair in result["pairs"]}
        diagnostics = {item["current_ref"]: item["reason"] for item in result["unresolved"]}
        for ref in sorted(components):
            pair = pairs.get(ref)
            if pair:
                old_ref = pair["previous_ref"]
                original = old_entries.get(old_ref) or _initial(
                    previous_scope, previous_artifact, role, old_ref
                )
                entry = {
                    key: original[key]
                    for key in ("lineage_id", "first_artifact", "first_ref", "role")
                }
                entry.update(
                    status="matched",
                    basis=pair["basis"],
                    previous_ref=old_ref,
                    previous_state=previous_state,
                )
                continued.add(entry["lineage_id"])
            else:
                entry = _initial(scope, artifact, role, ref)
                if entry["lineage_id"] in tombstones:
                    # Reimporting an old file cannot resurrect retired continuity.
                    entry["lineage_id"] = digest(
                        canonical([entry["lineage_id"], "reappearance", previous_state])
                    )
                entry.update(
                    status="unresolved", basis=diagnostics.get(ref, "no_unambiguous_strong_match")
                )
            entries[ref] = entry
            assigned.add(entry["lineage_id"])
        for ref in old_groups[role]:
            original = old_entries.get(ref) or _initial(
                previous_scope, previous_artifact, role, ref
            )
            lineage = original["lineage_id"]
            # Exact same bytes/ref produce the same deterministic initial ID.
            # This records an unchanged occurrence, never a portable-name match.
            if lineage not in continued and lineage not in assigned:
                tombstones[lineage] = {
                    **{
                        key: original[key]
                        for key in ("lineage_id", "first_artifact", "first_ref", "role")
                    },
                    "last_ref": ref,
                    "last_state": previous_state,
                    "last_artifact": previous_artifact,
                }
    if len(entries) + len(tombstones) > MAX_IDENTITIES:
        raise ValueError("Component lineage history exceeds its retained identity bound")
    ledger = {
        "format": FORMAT,
        "policy": POLICY,
        "scope": scope,
        "entries": entries,
        "tombstones": tombstones,
    }
    if len(canonical(ledger)) > MAX_LEDGER_BYTES:
        raise ValueError("Component lineage ledger exceeds its byte bound")
    return ledger
