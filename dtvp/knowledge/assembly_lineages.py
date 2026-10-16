"""Propagate pinned constituent identities without changing assembled payloads."""

from copy import deepcopy

from dtvp.knowledge.component_lineages import (
    FORMAT as SOURCE_FORMAT,
)
from dtvp.knowledge.component_lineages import (
    MAX_IDENTITIES,
    MAX_LEDGER_BYTES,
    POLICY,
    _components,
    _scope,
    _validate_prior,
    reconcile_lineages,
)
from dtvp.storage import canonical

FORMAT = "dtvp.assembled-component-lineages/1"


def assemble_lineages(
    selected, *, project_id, version, qualify, previous_identity=None, previous_state=None
):
    """Build additive identity metadata from already authorized selected inputs.

    Each selection is (part_id, source_state, source_inventory). Source ledger
    validation is shared with single-baseline imports. Legacy parts bootstrap
    exactly the same original-artifact/ref IDs as their next accepted import.
    """
    entries, tombstones, parts = {}, {}, []
    identities = set()
    for part_id, state, source in selected:
        if source.get("baseline", {}).get("part_id") != part_id:
            raise ValueError("Assembly identity part scope disagrees with selected input")
        ledger = source.get("identity")
        if ledger is None:
            ledger = reconcile_lineages({}, source, project_id=project_id, version=version)
            basis = "legacy_artifact_ref_bootstrap"
        else:
            if not isinstance(ledger, dict) or (
                ledger.get("format") != SOURCE_FORMAT
                or ledger.get("policy") != POLICY
                or ledger.get("scope") != _scope(source, project_id, version)
            ):
                raise ValueError("Assembly source identity ledger scope is inconsistent")
            _validate_prior(ledger, _components(source))
            basis = "retained_source_ledger"
        parts.append({"part_id": part_id, "state": state, "identity_basis": basis})
        for ref, item in ledger["entries"].items():
            qualified = qualify(part_id, ref)
            identity = item["lineage_id"]
            if qualified in entries or identity in identities or identity in tombstones:
                raise ValueError("Assembly component identity collision across selected parts")
            identities.add(identity)
            entries[qualified] = {
                **deepcopy(item),
                "source": {
                    "part_id": part_id,
                    "state": state,
                    "ref": ref,
                    "artifact_sha": source["baseline"]["artifact_sha"],
                },
            }
        for identity, item in ledger["tombstones"].items():
            if identity in tombstones or identity in identities:
                raise ValueError("Assembly retired identity collision across selected parts")
            tombstones[identity] = {
                **deepcopy(item),
                "last_ref": qualify(part_id, item["last_ref"]),
                "source": {"part_id": part_id, "state": state, "ref": item["last_ref"]},
            }
        if len(entries) + len(tombstones) > MAX_IDENTITIES:
            raise ValueError("Assembly identity ledger exceeds its retained occurrence bound")
    if previous_identity is not None:
        if not isinstance(previous_identity, dict) or (
            previous_identity.get("format") != FORMAT
            or previous_identity.get("policy") != POLICY
            or previous_identity.get("project_id") != project_id
        ):
            raise ValueError("Unsupported retained assembly identity ledger")
        old_entries, old_retired = (
            previous_identity.get("entries"),
            previous_identity.get("tombstones"),
        )
        if not isinstance(old_entries, dict) or not isinstance(old_retired, dict):
            raise ValueError("Malformed retained assembly identity ledger")
        if any(not isinstance(item, dict) for item in old_entries.values()):
            raise ValueError("Malformed retained assembly identity entry")
        groups = {"root": {}, "component": {}}
        for ref, item in old_entries.items():
            if item.get("role") not in groups:
                raise ValueError("Malformed retained assembly identity role")
            if not isinstance(item.get("source"), dict) or any(
                not isinstance(item["source"].get(field), str) or not item["source"][field]
                for field in ("part_id", "state", "ref", "artifact_sha")
            ):
                raise ValueError("Malformed retained assembly identity source provenance")
            groups[item["role"]][ref] = {}
        _validate_prior(previous_identity, groups)
        if (
            len(old_entries) + len(old_retired) > MAX_IDENTITIES
            or len(canonical(previous_identity)) > MAX_LEDGER_BYTES
        ):
            raise ValueError("Retained assembly identity ledger exceeds its bound")
        for identity, item in old_retired.items():
            if identity not in identities and identity not in tombstones:
                tombstones[identity] = deepcopy(item)
        for ref, item in old_entries.items():
            identity = item["lineage_id"]
            if identity not in identities and identity not in tombstones:
                tombstones[identity] = {
                    **deepcopy(item),
                    "last_ref": ref,
                    "last_state": previous_state,
                    "last_artifact": item.get("source", {}).get(
                        "artifact_sha", item["first_artifact"]
                    ),
                }
    ledger = {
        "format": FORMAT,
        "policy": POLICY,
        "project_id": project_id,
        "version": version,
        "parts": parts,
        "entries": entries,
        "tombstones": tombstones,
    }
    if len(entries) + len(tombstones) > MAX_IDENTITIES or len(canonical(ledger)) > MAX_LEDGER_BYTES:
        raise ValueError("Assembly identity ledger exceeds its retained bound")
    return ledger
