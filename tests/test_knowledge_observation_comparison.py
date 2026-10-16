"""Attributed source-fact deltas remain separate from software composition."""

import copy

import pytest

from dtvp.knowledge.comparison import compare_states, observation_changes
from dtvp.knowledge.workspace import load_sections
from tests.test_knowledge_assessments import journal as base_journal
from tests.test_knowledge_assessments import seed

journal = base_journal


def claim(*, source="scanner", part_id=None, state="a" * 64, ref="observed-lib", **facts):
    return {
        "source": source,
        "part_id": part_id,
        "state": state,
        "ref": ref,
        "component": {
            "bom-ref": ref,
            "name": "lib",
            "version": "1",
            "purl": "pkg:generic/lib@1",
            "dtvp_origin": {"state": state, "ref": ref},
            **facts,
        },
    }


def register(*assertions, target="lib"):
    return {
        "observation_assertions": {
            "format": "dtvp.observation-assertions/1",
            "components": {target: list(assertions)},
        }
    }


def attach(inventory):
    def update(sections):
        sections["inventory"].update(copy.deepcopy(inventory))

    return update


def test_changed_source_license_and_description_are_attributed_without_component_or_topology_edits(
    journal,
):
    first = seed(
        journal,
        modify=attach(
            register(
                claim(licenses=[{"expression": "MIT"}], description="First scanner description")
            )
        ),
    )
    second = seed(
        journal,
        parent=first,
        modify=attach(
            register(
                claim(
                    state="b" * 64,
                    ref="renamed",
                    licenses=[{"expression": "Apache-2.0"}],
                    description="Changed scanner description",
                )
            )
        ),
    )
    before = journal.head()
    result = compare_states(journal, "project", first, second)
    evidence = [row for row in result["items"] if row["category"] == "observation_evidence"]
    assert len(evidence) == 1
    row = evidence[0]
    assert row["key"] == ["lib", None, "scanner"]
    assert row["changed_fields"] == ["description", "licenses"]
    assert row["classifications"] == ["evidence", "material", "source_license"]
    assert row["before"]["facts"][0]["licenses"] == [{"expression": "MIT"}]
    assert row["after"]["provenance"][0]["state"] == "b" * 64
    assert row["after"]["provenance"][0]["ref"] == "renamed"
    assert row["after"]["provenance"][0]["component_origin"]["state"] == "b" * 64
    assert not any(row["category"] in {"component", "dependency"} for row in result["items"])
    assert (
        load_sections(journal, first)["assessments"]
        == load_sections(journal, second)["assessments"]
    )
    assert journal.head() == before


def test_nightly_local_reference_state_and_origin_churn_is_not_material_evidence(journal):
    old = claim(description="Same claim", licenses=[{"expression": "MIT"}])
    first = seed(journal, modify=attach(register(old)))
    second = seed(
        journal,
        parent=first,
        modify=attach(
            register(
                claim(
                    state="c" * 64,
                    ref="new-bom-ref",
                    description="Same claim",
                    licenses=[{"expression": "MIT"}],
                )
            )
        ),
    )
    result = compare_states(journal, "project", first, second)
    assert not result["items"]
    assert result["observation_evidence"]["provenance_only_groups"] == 1
    assert result["summary"]["by_classification"] == {}


def test_same_package_stays_separate_by_canonical_occurrence_part_and_source():
    before = register(
        claim(source="scanner-a", part_id="application", licenses=[{"expression": "MIT"}]),
        claim(source="scanner-b", part_id="container", licenses=[{"expression": "BSD-3-Clause"}]),
    )
    after = copy.deepcopy(before)
    after["observation_assertions"]["components"]["lib"][0]["component"]["licenses"] = [
        {"expression": "Apache-2.0"}
    ]
    rows, summary = observation_changes(before, after)
    assert len(rows) == 1 and rows[0]["key"] == ["lib", "application", "scanner-a"]
    assert summary["scoped_groups_before"] == summary["scoped_groups_after"] == 2
    other = register(
        claim(source="scanner-a", part_id="application", licenses=[{"expression": "MIT"}]),
        target="other-part-lib",
    )
    rows, _ = observation_changes(
        register(
            claim(source="scanner-a", part_id="application", licenses=[{"expression": "MIT"}])
        ),
        other,
    )
    assert {row["change"] for row in rows} == {"added", "removed"}
    assert len(rows) == 2


def test_duplicates_and_assertion_order_do_not_change_facts_or_collapse_conflicts():
    first = claim(description="One claim")
    second = claim(source="other", description="Conflicting claim")
    assert observation_changes(register(first, second, first), register(second, first))[0] == []
    rows, _ = observation_changes(register(first), register(first, second))
    assert len(rows) == 1 and rows[0]["key"][2] == "other"
    assert rows[0]["classifications"] == ["added", "evidence", "material"]


def test_unknown_component_and_source_attributes_remain_material():
    before = register(claim(properties=[{"name": "exposure", "value": "internal"}]))
    after = copy.deepcopy(before)
    after["observation_assertions"]["components"]["lib"][0]["component"]["properties"][0][
        "value"
    ] = "external"
    rows, _ = observation_changes(before, after)
    assert rows[0]["changed_fields"] == ["properties"]
    after = copy.deepcopy(before)
    after["observation_assertions"]["components"]["lib"][0]["confidence"] = "low"
    rows, _ = observation_changes(before, after)
    assert rows[0]["changed_fields"] == ["source_attributes"]
    assert rows[0]["after"]["claims"][0]["attributes"] == {"confidence": "low"}


def test_evidence_pagination_totals_and_history_pins_are_stable(journal):
    first = seed(journal, modify=attach(register(claim(source="one"), claim(source="two"))))
    second = seed(
        journal,
        parent=first,
        modify=attach(
            register(
                claim(source="one", description="Changed one"),
                claim(source="two", description="Changed two"),
            )
        ),
    )
    full = compare_states(journal, "project", first, second, limit=200)
    pages = [
        compare_states(journal, "project", first, second, offset=index, limit=1)
        for index in range(full["total"])
    ]
    assert [page["items"][0] for page in pages] == full["items"]
    assert all(
        page["summary"] == full["summary"]
        and page["observation_evidence"] == full["observation_evidence"]
        for page in pages
    )
    assert full["summary"]["by_category"]["observation_evidence"] == 2
    assert compare_states(journal, "project", first, second, limit=200) == full


def test_bounded_comparison_rejects_without_truncating_evidence(monkeypatch):
    import dtvp.knowledge.comparison as comparison

    monkeypatch.setattr(comparison, "MAX_OBSERVATION_ASSERTIONS", 1)
    with pytest.raises(ValueError, match="100000 assertions"):
        observation_changes(register(claim(source="one"), claim(source="two")), {})
    monkeypatch.setattr(comparison, "MAX_OBSERVATION_ASSERTIONS", 100000)
    monkeypatch.setattr(comparison, "MAX_OBSERVATION_BYTES", 20)
    with pytest.raises(ValueError, match="32 MiB"):
        observation_changes(register(claim(description="A sufficiently long source fact")), {})


def test_unknown_register_version_fails_closed_and_missing_register_stays_compatible():
    assert observation_changes({}, {})[0] == []
    data = register(claim())
    data["observation_assertions"]["format"] = "dtvp.observation-assertions/unknown"
    with pytest.raises(ValueError, match="Unsupported"):
        observation_changes(data, {})


def test_component_origin_only_changes_are_counted_as_provenance_without_material_rows():
    before = register(claim())
    after = copy.deepcopy(before)
    after["observation_assertions"]["components"]["lib"][0]["component"]["dtvp_origin"]["state"] = (
        "f" * 64
    )
    rows, summary = observation_changes(before, after)
    assert not rows and summary["provenance_only_groups"] == 1
