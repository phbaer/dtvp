"""Stable metadata never changes source-local graph or approval semantics."""

import json
from copy import deepcopy
from pathlib import Path

import pytest

from dtvp.knowledge import component_lineages as lineages
from dtvp.knowledge.assessments import Target, coverage_status, target_fingerprint, target_key
from dtvp.knowledge.component_inventory import component_rows
from dtvp.knowledge.journal import Journal
from dtvp.knowledge.service import import_inventory
from dtvp.knowledge.workspace import load_sections


def inventory(ref="a", purl="pkg:generic/acme/a@1", *, artifact="a" * 64, **component):
    return {
        "baseline": {"source": "nightly", "artifact_sha": artifact},
        "component:a": {
            "bom-ref": ref,
            "type": "library",
            "name": "a",
            "version": "1",
            **({"purl": purl} if purl else {}),
            **component,
        },
    }


def reconcile(old, new, **changes):
    return lineages.reconcile_lineages(
        old,
        new,
        project_id="product",
        version="1",
        previous_state="b" * 64 if old else None,
        previous_version="1" if old else None,
        **changes,
    )


def test_exact_renamed_occurrence_bootstraps_old_states_and_retains_tombstone():
    old = inventory()
    new = inventory("renamed", artifact="c" * 64)
    before = deepcopy((old, new))
    bootstrap = reconcile({}, old)
    ledger = reconcile(old, new)
    assert ledger["entries"]["renamed"]["lineage_id"] == bootstrap["entries"]["a"]["lineage_id"]
    assert ledger["entries"]["renamed"]["basis"] == "exact_purl"
    assert ledger["entries"]["renamed"]["previous_ref"] == "a"
    assert (old, new) == before
    new["identity"] = ledger
    empty = {"baseline": {"source": "nightly", "artifact_sha": "d" * 64}}
    removed = reconcile(new, empty)
    identity = ledger["entries"]["renamed"]["lineage_id"]
    assert removed["entries"] == {}
    assert removed["tombstones"][identity]["last_ref"] == "renamed"
    empty["identity"] = removed
    returned = reconcile(empty, new)
    assert returned["entries"]["renamed"]["lineage_id"] != identity
    assert identity in returned["tombstones"]


@pytest.mark.parametrize(
    "changes", [{"purl": None}, {"hashes": [{"alg": "SHA-256", "content": "f" * 64}]}]
)
def test_missing_or_conflicting_markers_never_reuse_name_or_reference(changes):
    old = inventory(hashes=[{"alg": "SHA-256", "content": "e" * 64}])
    old["identity"] = reconcile({}, old)
    new = inventory(artifact="c" * 64, **changes)
    ledger = reconcile(old, new)
    assert ledger["entries"]["a"]["status"] == "unresolved"
    assert ledger["entries"]["a"]["lineage_id"] != old["identity"]["entries"]["a"]["lineage_id"]
    assert old["identity"]["entries"]["a"]["lineage_id"] in ledger["tombstones"]


def test_duplicate_packages_stay_distinct_and_unresolved():
    old, new = inventory(), inventory("b", artifact="c" * 64)
    new["component:c"] = {**new["component:a"], "bom-ref": "c"}
    ledger = reconcile(old, new)
    assert len({entry["lineage_id"] for entry in ledger["entries"].values()}) == 2
    assert {entry["status"] for entry in ledger["entries"].values()} == {"unresolved"}


def test_digest_only_continuity_and_identifier_free_occurrences():
    old = inventory(purl=None, hashes=[{"alg": "SHA-256", "content": "e" * 64}])
    new = deepcopy(old)
    new["baseline"]["artifact_sha"] = "c" * 64
    new["component:a"]["bom-ref"] = "renamed"
    ledger = reconcile(old, new)
    assert ledger["entries"]["renamed"]["basis"] == "scoped_strong_digest"
    incomplete = {"baseline": old["baseline"], "component:a": {"bom-ref": "a"}}
    identity = reconcile({}, incomplete)["entries"]["a"]
    assert len(identity["lineage_id"]) == 64
    assert identity["status"] == "unresolved"


def test_root_and_dependency_are_not_matched_across_roles():
    old = inventory()
    new = {
        "baseline": {**old["baseline"], "artifact_sha": "c" * 64},
        "root": {**old["component:a"], "bom-ref": "root"},
    }
    ledger = reconcile(old, new)
    assert ledger["entries"]["root"]["status"] == "unresolved"
    assert len(ledger["tombstones"]) == 1


@pytest.mark.parametrize("change", ["version", "source", "part", "boundary"])
def test_continuity_is_binding_scoped(change):
    old, new = inventory(), inventory("b", artifact="c" * 64)
    old["identity"] = reconcile({}, old)
    options = {}
    if change == "version":
        options["previous_version"] = "older"
    elif change == "source":
        new["baseline"]["source"] = "other"
    elif change == "part":
        new["baseline"]["part_id"] = "backend"
    else:
        new["baseline"]["collection"] = {"target": "other"}
    ledger = lineages.reconcile_lineages(
        old,
        new,
        project_id="product",
        version="1",
        previous_state="b" * 64,
        previous_version=options.get("previous_version", "1"),
    )
    assert ledger["entries"]["b"]["lineage_id"] != old["identity"]["entries"]["a"]["lineage_id"]
    assert ledger["tombstones"] == {}


def test_ledger_does_not_change_frozen_assessment_fingerprint_or_old_rows():
    case = json.loads(
        (Path(__file__).parent / "fixtures/knowledge-target-fingerprints.json").read_text()
    )["cases"][0]
    sections = case["sections"]
    assert all(row["identity"] is None for row in component_rows(sections))
    before = deepcopy(sections)
    sections["inventory"]["identity"] = reconcile(
        {},
        {
            **sections["inventory"],
            "baseline": {**sections["inventory"]["baseline"], "artifact_sha": "a" * 64},
        },
    )
    assert (
        target_fingerprint(sections, case["version"], case["context_id"], case["vulnerability_id"])
        == case["fingerprint"]
    )
    assert {
        key: value for key, value in sections["inventory"].items() if key != "identity"
    } == before["inventory"]
    assert all(row["identity"] for row in component_rows(sections))


def test_bounds_fail_closed_without_mutating_inputs(monkeypatch):
    old, new = inventory(), inventory(artifact="c" * 64, version="2")
    old["identity"] = reconcile({}, old)
    before = deepcopy(old)
    monkeypatch.setattr(lineages, "MAX_IDENTITIES", 1)
    with pytest.raises(ValueError, match="retained identity bound"):
        reconcile(old, new)
    assert old == before
    monkeypatch.setattr(lineages, "MAX_LEDGER_BYTES", 1)
    with pytest.raises(ValueError, match="byte bound"):
        reconcile({}, inventory())


def test_import_lifecycle_replay_and_explicit_version_fork_continue_lineage(tmp_path, bom):
    journal = Journal(tmp_path / "journal")

    def apply(document, build, expected=None, **changes):
        return import_inventory(
            journal,
            project_id="product",
            version="1",
            actor_id="analyst",
            request_id=f"import-{build}",
            expected=expected,
            source="nightly",
            build_number=build,
            occurred_at="2026-10-15T00:00:00+00:00",
            sbom=document,
            **changes,
        )

    first_receipt = apply(bom, 1)
    first = first_receipt[1].updates[0].target
    old = load_sections(journal, first)
    modified = deepcopy(bom)
    target = next(c for c in modified["components"] if c.get("purl"))
    old_ref = target["bom-ref"]
    target["bom-ref"] = "renamed-component"
    for edge in modified.get("dependencies", []):
        if edge["ref"] == old_ref:
            edge["ref"] = target["bom-ref"]
        edge["dependsOn"] = [
            target["bom-ref"] if ref == old_ref else ref for ref in edge.get("dependsOn", [])
        ]
    for vuln in modified.get("vulnerabilities", []):
        for affected in vuln.get("affects", []):
            if affected["ref"] == old_ref:
                affected["ref"] = target["bom-ref"]
    second = apply(modified, 2, first)[1].updates[0].target
    current = load_sections(journal, second)
    assert (
        current["inventory"]["identity"]["entries"][target["bom-ref"]]["lineage_id"]
        == old["inventory"]["identity"]["entries"][old_ref]["lineage_id"]
    )
    assert current["assessments"] == old["assessments"]
    assert apply(bom, 1) == first_receipt
    fork = (
        import_inventory(
            journal,
            project_id="product",
            version="2",
            actor_id="analyst",
            request_id="fork",
            expected=None,
            predecessor=second,
            source="nightly",
            build_number=1,
            occurred_at="2026-10-15T00:00:00+00:00",
            sbom=modified,
        )[1]
        .updates[0]
        .target
    )
    assert (
        load_sections(journal, fork)["inventory"]["identity"]["entries"][target["bom-ref"]][
            "lineage_id"
        ]
        == current["inventory"]["identity"]["entries"][target["bom-ref"]]["lineage_id"]
    )


def test_explicit_predecessor_keeps_ids_but_not_assessment_coverage():
    old, new = inventory(), inventory("renamed", artifact="c" * 64)
    old["identity"] = reconcile({}, old)
    ledger = lineages.reconcile_lineages(
        old,
        new,
        project_id="product",
        version="2",
        previous_state="b" * 64,
        previous_version="1",
        explicit_predecessor=True,
    )
    assert (
        ledger["entries"]["renamed"]["lineage_id"] == old["identity"]["entries"]["a"]["lineage_id"]
    )
    assert ledger["scope"]["version"] == "2"
    # Coverage explicitly names versions even when semantic fingerprints match.
    case = json.loads(
        (Path(__file__).parent / "fixtures/knowledge-target-fingerprints.json").read_text()
    )["cases"][0]
    sections = case["sections"]
    sections["inventory"]["identity"] = ledger
    source_target = Target(
        version="1", context_id=case["context_id"], vulnerability_id=case["vulnerability_id"]
    )
    target = source_target.model_copy(update={"version": "2"})
    sections["assessments"]["old"] = {
        "payload": {
            "targets": [source_target.model_dump()],
            "created_at": "2026-10-15T00:00:00+00:00",
        }
    }
    sections["reviews"]["review:" + target_key(target)] = {"target": source_target.model_dump()}
    coverage = coverage_status(None, sections, "2", case["context_id"], case["vulnerability_id"])
    assert coverage["status"] == "unassessed"
    assert coverage["approved"] is False
    new["identity"] = ledger
    later = inventory("next", artifact="d" * 64)
    later["identity"] = lineages.reconcile_lineages(
        new, later, project_id="product", version="2", previous_state="e" * 64, previous_version="2"
    )
    assert (
        later["identity"]["entries"]["next"]["lineage_id"]
        == ledger["entries"]["renamed"]["lineage_id"]
    )


@pytest.mark.parametrize(
    "damage", ["missing-entry", "bad-id", "wrong-role", "duplicate", "tombstone"]
)
def test_malformed_retained_ledger_fails_closed(damage):
    old, new = inventory(), inventory("b", artifact="c" * 64)
    old["identity"] = reconcile({}, old)
    entry = old["identity"]["entries"]["a"]
    if damage == "missing-entry":
        old["identity"]["entries"].clear()
    elif damage == "bad-id":
        entry["lineage_id"] = "invalid"
    elif damage == "wrong-role":
        entry["role"] = "root"
    elif damage == "duplicate":
        old["component:b"] = {**old["component:a"], "bom-ref": "b"}
        old["identity"]["entries"]["b"] = deepcopy(entry)
    else:
        old["identity"]["tombstones"]["f" * 64] = {"lineage_id": "f" * 64}
    with pytest.raises(ValueError, match="lineage"):
        reconcile(old, new)
