"""Finite version selection never widens assessment or review coverage."""

import pytest

from dtvp.knowledge import coverage_candidates as service
from dtvp.knowledge import version_selection as selection_service
from dtvp.knowledge.version_selection import VersionSelection, numeric_release, select_versions
from dtvp.storage import canonical, digest
from tests.test_knowledge_coverage_candidates import candidates, parallel, seed
from tests.test_knowledge_coverage_candidates import journal as source_journal

journal = source_journal


@pytest.mark.parametrize(
    "label",
    [
        "7.1",
        "v7.1.1",
        "7.1.1-rc.1",
        "7.1.1+build",
        "07.1.1",
        "release/7.1.1",
        "7.1.1.0",
        "７.１.１",
    ],
)
def test_other_version_schemes_are_unknown_without_coercion(label):
    assert numeric_release(label) is None
    heads = {label: "a" * 64, "7.1.1": "b" * 64}
    result = select_versions(heads, VersionSelection())
    assert result["selected_versions"] == ["7.1.1"]
    assert (
        next(row for row in result["versions"] if row["version"] == label)["status"]
        == "unknown_ordering"
    )
    assert label in select_versions(heads, VersionSelection(include=[label]))["selected_versions"]


@pytest.mark.parametrize(
    "value",
    [
        {"lower": "7.2.0", "upper": "7.1.1"},
        {"lower": "v7.1.1"},
        {"upper": "7.1"},
        {"include": ["main", "main"]},
        {"exclude": ["main", "main"]},
        {"include": ["main"], "exclude": ["main"]},
    ],
)
def test_invalid_bounds_and_overlapping_names_fail_closed(value):
    with pytest.raises(ValueError):
        VersionSelection(**value)


def test_numeric_membership_is_inclusive_and_exclusions_explicit():
    heads = {
        version: "a" * 64 for version in ["6.15.6", "7.1.1", "7.1.2", "7.2.0", "7.10.0", "main"]
    }
    selected = select_versions(
        heads, VersionSelection(lower="7.1.1", upper="7.2.0", include=["main"], exclude=["7.1.2"])
    )
    assert selected["selected_versions"] == ["7.1.1", "7.2.0", "main"]
    assert selected["captured_versions"] == 6
    with pytest.raises(ValueError, match="current product branches"):
        select_versions(heads, VersionSelection(include=["missing"]))


def test_complete_head_budget_is_checked_before_iterating(monkeypatch):
    monkeypatch.setattr(selection_service, "MAX_VERSION_HEADS", 1)
    with pytest.raises(ValueError, match="head budget"):
        select_versions({"7.1.1": "a", "7.1.2": "b"}, VersionSelection())


def test_opt_in_selection_binds_all_heads_and_preserves_unfiltered_contract(journal):
    parallel(journal)
    baseline = candidates(journal)
    assert candidates(journal, version_selection=None) == baseline
    # Original v1 digest/DTO derivation remains byte-identical when omitted.
    original = {
        key: value
        for key, value in baseline.items()
        if key not in {"items", "total", "next_offset", "preview_digest"}
    }
    assert digest(canonical([original, baseline["items"]])) == baseline["preview_digest"]
    selector = VersionSelection(lower="7.1.1", upper="7.2.0", exclude=["7.1.2"])
    before = journal.head()
    first = candidates(journal, version_selection=selector, limit=1)
    second = candidates(journal, version_selection=selector, offset=1, limit=1)
    assert first["total"] == first["statistics"]["versions"] == 2
    assert first["preview_digest"] == second["preview_digest"]
    assert first["heads"] == baseline["heads"]
    assert journal.head() == before
    seed(
        journal, version="8.0.0"
    )  # Outside the selected range, still invalidates full head-set pin.
    newer = candidates(journal, version_selection=selector, limit=1)
    assert newer["preview_digest"] != first["preview_digest"]
    assert newer["total"] == first["total"]
    assert all(row["coverage"]["status"] == "unassessed" for row in newer["items"])


def test_selected_context_budget_fails_instead_of_truncating(journal, monkeypatch):
    parallel(journal)
    monkeypatch.setattr(service, "MAX_SELECTION_ROWS", 1)
    with pytest.raises(ValueError, match="context budget"):
        candidates(journal, version_selection=VersionSelection())


def test_complete_head_budget_precedes_historical_reachability_scan(journal, monkeypatch):
    parallel(journal)
    source = candidates(journal)["source"]["state"]
    seed(journal, version="7.1.1", parent=source)
    monkeypatch.setattr(selection_service, "MAX_VERSION_HEADS", 1)

    def forbidden(*args, **kwargs):
        pytest.fail("Historical reachability scanned before complete head-budget admission")

    monkeypatch.setattr(service, "reachable_states", forbidden)
    with pytest.raises(ValueError, match="head budget"):
        candidates(journal, source=source, version_selection=VersionSelection())
