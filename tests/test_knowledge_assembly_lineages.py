"""Assembly preserves constituent identity without merging package occurrences."""

from copy import deepcopy

import pytest

from dtvp.knowledge import assembly_lineages
from dtvp.knowledge.assembly import (
    AssemblyInput,
    build_assembly_candidate,
    namespaced_ref,
    publish_assembly,
)
from dtvp.knowledge.assessments import target_fingerprint
from dtvp.knowledge.component_inventory import component_rows
from dtvp.knowledge.component_lineages import reconcile_lineages
from dtvp.knowledge.journal import Journal
from dtvp.knowledge.service import import_inventory
from dtvp.knowledge.workspace import load_sections


def source(part="backend", artifact="a" * 64):
    inventory = {
        "baseline": {"part_id": part, "source": "nightly", "artifact_sha": artifact},
        "root": {
            "bom-ref": "root",
            "name": "app",
            "type": "application",
            "version": "1",
            "purl": "pkg:generic/app@1",
        },
        "component:root": {
            "bom-ref": "root",
            "name": "app",
            "type": "application",
            "version": "1",
            "purl": "pkg:generic/app@1",
        },
        "component:lib": {
            "bom-ref": "lib",
            "name": "lib",
            "version": "1",
            "purl": "pkg:generic/lib@1",
        },
    }
    inventory["identity"] = reconcile_lineages({}, inventory, project_id="product", version="1")
    return inventory


def assemble(selected, **changes):
    return assembly_lineages.assemble_lineages(
        selected, project_id="product", version="1", qualify=namespaced_ref, **changes
    )


def test_two_parts_keep_distinct_ids_and_original_provenance_with_one_root_entry():
    backend, frontend = source(), source("frontend")
    before = deepcopy((backend, frontend))
    ledger = assemble([("backend", "b" * 64, backend), ("frontend", "c" * 64, frontend)])
    assert len(ledger["entries"]) == 4
    assert len({entry["lineage_id"] for entry in ledger["entries"].values()}) == 4
    for part, state, source_inventory in [
        ("backend", "b" * 64, backend),
        ("frontend", "c" * 64, frontend),
    ]:
        for ref in ("root", "lib"):
            entry = ledger["entries"][namespaced_ref(part, ref)]
            assert entry["lineage_id"] == source_inventory["identity"]["entries"][ref]["lineage_id"]
            assert entry["source"] == {
                "part_id": part,
                "state": state,
                "ref": ref,
                "artifact_sha": "a" * 64,
            }
    assert (backend, frontend) == before


def test_legacy_bootstrap_agrees_with_future_import_identity():
    legacy = source()
    expected = legacy.pop("identity")
    ledger = assemble([("backend", "b" * 64, legacy)])
    assert ledger["parts"][0]["identity_basis"] == "legacy_artifact_ref_bootstrap"
    assert {key: value["lineage_id"] for key, value in ledger["entries"].items()} == {
        namespaced_ref("backend", key): value["lineage_id"]
        for key, value in expected["entries"].items()
    }


def test_pinned_renames_and_deselection_keep_continuity_and_tombstones():
    old = source()
    previous = assemble([("backend", "b" * 64, old)])
    current = deepcopy(old)
    current["baseline"]["artifact_sha"] = "c" * 64
    current["component:lib"]["bom-ref"] = "renamed"
    current["identity"] = reconcile_lineages(
        old,
        current,
        project_id="product",
        version="1",
        previous_state="b" * 64,
        previous_version="1",
    )
    ledger = assemble(
        [("backend", "d" * 64, current)], previous_identity=previous, previous_state="e" * 64
    )
    assert (
        ledger["entries"][namespaced_ref("backend", "renamed")]["lineage_id"]
        == previous["entries"][namespaced_ref("backend", "lib")]["lineage_id"]
    )
    assert ledger["tombstones"] == {}
    removed = assemble([], previous_identity=ledger, previous_state="f" * 64)
    assert len(removed["tombstones"]) == 2
    assert {value["last_state"] for value in removed["tombstones"].values()} == {"f" * 64}
    assert {value["last_artifact"] for value in removed["tombstones"].values()} == {"c" * 64}
    assert (
        assemble([], previous_identity=removed, previous_state="a" * 64)["tombstones"]
        == removed["tombstones"]
    )


def test_source_tombstones_stay_qualified_and_retained():
    old = source()
    current = deepcopy(old)
    current.pop("component:lib")
    current["baseline"]["artifact_sha"] = "c" * 64
    current["identity"] = reconcile_lineages(
        old,
        current,
        project_id="product",
        version="1",
        previous_state="b" * 64,
        previous_version="1",
    )
    ledger = assemble([("backend", "d" * 64, current)])
    tombstone = next(iter(ledger["tombstones"].values()))
    assert tombstone["last_ref"] == namespaced_ref("backend", "lib")
    assert tombstone["source"]["ref"] == "lib"
    assert tombstone["last_state"] == "b" * 64


def test_malformed_scope_and_global_bounds_fail_closed(monkeypatch):
    malformed = source()
    malformed["identity"]["scope"]["part_id"] = "other"
    with pytest.raises(ValueError, match="scope"):
        assemble([("backend", "b" * 64, malformed)])
    monkeypatch.setattr(assembly_lineages, "MAX_IDENTITIES", 3)
    with pytest.raises(ValueError, match="bound"):
        assemble([("backend", "b" * 64, source()), ("frontend", "c" * 64, source("frontend"))])


def test_real_assembly_rows_carry_lineages_without_component_or_fingerprint_changes(tmp_path, bom):
    journal = Journal(tmp_path / "journal")
    states = {}
    for part in ("backend", "frontend"):
        states[part] = (
            import_inventory(
                journal,
                project_id="product",
                version="1",
                actor_id="pipeline",
                request_id=part,
                expected=None,
                source="nightly",
                build_number=1,
                occurred_at="2026-10-15T00:00:00+00:00",
                part_id=part,
                sbom=bom,
            )[1]
            .updates[0]
            .target
        )
    data = AssemblyInput(
        request_id="assemble",
        expected=None,
        parts=[
            {"part_id": part, "state": state, "required": True} for part, state in states.items()
        ],
    )
    candidate = build_assembly_candidate(journal, project_id="product", version="1", data=data)
    before = deepcopy(candidate["sections"])
    state = (
        publish_assembly(
            journal, project_id="product", version="1", actor_id="pipeline", data=data
        )[1]
        .updates[0]
        .target
    )
    sections = load_sections(journal, state)
    rows = component_rows(sections)
    assert len(rows) == 2 * (len(bom["components"]) + 1)
    assert all(row["identity"] for row in rows)
    assert sections["inventory"] == before["inventory"]
    without_ledger = deepcopy(sections)
    without_ledger["inventory"].pop("identity")
    checked = 0
    for key, context in sections["ownership"].items():
        if not key.startswith("context:"):
            continue
        for claim in sections["vulnerabilities"].values():
            if claim["ref"] != context["component_ref"]:
                continue
            fingerprint = target_fingerprint(sections, "1", context["id"], claim["identifier"])
            assert fingerprint is not None
            assert (
                target_fingerprint(without_ledger, "1", context["id"], claim["identifier"])
                == fingerprint
            )
            checked += 1
    assert checked > 0
    for row in rows:
        origin = row["component"]["dtvp_origin"]
        source_inventory = load_sections(journal, states[origin["part_id"]])["inventory"]
        assert (
            row["identity"]["lineage_id"]
            == source_inventory["identity"]["entries"][origin["ref"]]["lineage_id"]
        )
    # The exact same captured assembly request replays its original receipt.
    assert (
        publish_assembly(
            journal, project_id="product", version="1", actor_id="pipeline", data=data
        )[1]
        .updates[0]
        .target
        == state
    )
