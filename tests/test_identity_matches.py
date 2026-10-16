"""Identity reports stay scoped, deterministic and read-only."""

from copy import deepcopy

import pytest

from dtvp.knowledge.identity_matches import _groups, identity_matches
from dtvp.knowledge.journal import SECTIONS, Journal, Ref, Update


@pytest.fixture
def journal(tmp_path):
    return Journal(tmp_path / "journal")


def inventory(ref="old", **changes):
    return {
        "baseline": {"collection": {}},
        "component:" + ref: {
            "bom-ref": ref,
            "purl": "pkg:maven/org.example/lib@1",
            "name": "lib",
            "version": "1",
        },
        **changes,
    }


def publish(journal, data, parent=None):
    sections = {name: {} for name in SECTIONS}
    sections["inventory"] = data
    state = journal.snapshot(
        project_id="project",
        version="1",
        actor_id="test",
        reason="Test identity",
        sections=sections,
        parents=[parent] if parent else [],
    )
    journal.publish(
        request_id=state,
        fingerprint=state,
        updates=[Update(ref=Ref(project_id="project", name="1"), expected=parent, target=state)],
    )
    return state


def test_ref_rename_matches_without_changing_states_or_coverage(journal):
    source = publish(journal, inventory())
    target = publish(journal, inventory("new"), source)
    before = journal.head()
    result = identity_matches(journal, "project", source, target)
    assert result["items"] == [
        {
            "kind": "component",
            "source_id": "old",
            "target_id": "new",
            "basis": "exact_purl",
            "scope": {"part_id": None, "role": "component"},
        }
    ]
    assert result["summary"]["matched"] == 1
    assert journal.head() == before
    assert identity_matches(journal, "project", source, target) == result


def test_root_and_distinct_part_instances_never_match_each_other(journal):
    source = publish(journal, inventory())
    new = inventory("new")
    new["root"] = new.pop("component:new")
    target = publish(journal, new, source)
    assert not identity_matches(journal, "project", source, target)["items"]
    new = inventory("new")
    new["component:new"]["dtvp_origin"] = {"part_id": "other"}
    target = publish(journal, new, target)
    assert not identity_matches(journal, "project", source, target)["items"]


def test_root_alias_not_counted_twice_and_scope_changes_block(journal):
    old = inventory()
    component = old["component:old"]
    component["dtvp_origin"] = {"part_id": "service"}
    old["part-root:service"] = deepcopy(component)
    old["assembly"] = {
        "parts": [{"part_id": "service", "baseline": {"collection": {"platform": "linux"}}}]
    }
    assert sum(map(len, _groups(old).values())) == 1
    source = publish(journal, old)
    new = deepcopy(old)
    new["assembly"]["parts"][0]["baseline"]["collection"]["platform"] = "windows"
    target = publish(journal, new, source)
    result = identity_matches(journal, "project", source, target)
    assert not result["items"]
    assert result["summary"]["scope_compatible"] is False
    assert result["unresolved"][0]["reason"] == "collection_scope_changed"


def test_missing_coordinates_stay_unresolved_and_diagnostics_bounded(journal):
    source = publish(journal, inventory())
    new = {"baseline": {"collection": {}}}
    new.update({f"component:{i}": {"bom-ref": str(i), "name": "common"} for i in range(150)})
    target = publish(journal, new, source)
    result = identity_matches(journal, "project", source, target)
    assert result["summary"]["unresolved"] == 150
    assert len(result["unresolved"]) == 100
    assert result["diagnostics_truncated"]


def test_digest_independent_of_page_and_foreign_or_unpublished_states_rejected(journal):
    old = inventory()
    old["component:other"] = {"bom-ref": "other", "purl": "pkg:generic/other@1"}
    source = publish(journal, old)
    target = publish(journal, deepcopy(old), source)
    first = identity_matches(journal, "project", source, target, limit=1)
    second = identity_matches(journal, "project", source, target, offset=1, limit=1)
    assert first["report_digest"] == second["report_digest"]
    assert first["items"] != second["items"]
    with pytest.raises(ValueError, match="committed"):
        identity_matches(journal, "other", source, target)
    with pytest.raises(ValueError):
        identity_matches(journal, "project", source, target, limit=201)
