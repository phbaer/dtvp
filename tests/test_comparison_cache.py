"""Historical caches accelerate reads without retaining authority or shared DTOs."""

import shutil
from concurrent.futures import ThreadPoolExecutor

import pytest

from dtvp.knowledge import comparison, comparison_cache
from dtvp.knowledge.comparison_cache import ComparisonCache, cache_for, cache_key
from dtvp.knowledge.journal import Journal
from dtvp.storage import canonical
from tests.test_knowledge_assessments import seed


def test_byte_and_entry_limits_lru_expiry_and_oversized_bypass():
    now = [0]
    cache = ComparisonCache(
        max_bytes=100, max_entry_bytes=60, max_entries=2, ttl=5, clock=lambda: now[0]
    )
    cache.put("a", {"value": "a" * 25})
    cache.put("b", {"value": "b" * 25})
    assert cache.get("a")["value"] == "a" * 25
    cache.put("c", {"value": "c" * 25})
    assert cache.get("b") is None
    cache.put("large", {"value": "x" * 100})
    assert cache.get("large") is None
    assert cache.get("a") is not None and cache.get("c") is not None
    cache.put("a", {"value": "new"})
    assert cache._bytes == sum(len(entry[1]) for entry in cache._entries.values()) <= 100
    now[0] = 4
    assert cache.get("a") == {"value": "new"}
    now[0] = 5
    assert cache.get("a") is None and cache.get("c") is None
    assert cache._bytes == 0
    # A separate byte bound applies even while entry capacity remains available.
    cache = ComparisonCache(max_bytes=50, max_entry_bytes=50, max_entries=10)
    cache.put("a", {"value": "a" * 20})
    cache.put("b", {"value": "b" * 20})
    assert cache.get("a") is None and cache.get("b") is not None


def test_concurrent_gets_are_detached_and_budget_remains_bounded():
    cache = ComparisonCache(max_bytes=500, max_entry_bytes=100, max_entries=4)
    cache.put("fixed", {"items": [1]})

    def read(_):
        value = cache.get("fixed")
        value["items"].append(2)
        return value

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert all(value == {"items": [1, 2]} for value in pool.map(read, range(50)))
    assert cache.get("fixed") == {"items": [1]}
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda index: cache.put(str(index), {"items": [index]}), range(100)))
    assert len(cache._entries) <= 4 and cache._bytes <= 500


def test_algorithm_scope_and_identical_hashes_in_other_journals_never_share_entries(
    tmp_path, monkeypatch
):
    first = Journal(tmp_path / "first")
    state = seed(first)
    key = cache_key("project", state, state)
    cache_for(first).put(key, {"items": []})
    shutil.copytree(first.root, tmp_path / "second")
    second = Journal(tmp_path / "second")
    assert second.state(state) == first.state(state)
    assert cache_for(second).get(key) is None
    assert cache_key("other-project", state, state) != key
    monkeypatch.setattr(comparison_cache, "ALGORITHM_VERSION", "new-algorithm")
    assert cache_for(first).get(cache_key("project", state, state)) is None


def test_pages_reuse_exact_full_result_but_revalidate_membership_and_never_cache_errors(
    tmp_path, monkeypatch
):
    journal = Journal(tmp_path / "journal")
    before = seed(journal)
    after = seed(
        journal,
        parent=before,
        modify=lambda sections: sections["inventory"]["component:lib"].update(version="2"),
    )
    original = comparison._compare_states
    calls = []

    def build(*args):
        calls.append(1)
        return original(*args)

    monkeypatch.setattr(comparison, "_compare_states", build)
    first = comparison.compare_states(journal, "project", before, after, limit=1)
    full = comparison.compare_states(journal, "project", before, after, limit=200)
    assert len(calls) == 1 and first["total"] == full["total"]
    assert canonical(first["items"]) == canonical(full["items"][:1])
    first["items"][0]["classifications"].append("caller mutation")
    assert (
        "caller mutation"
        not in comparison.compare_states(journal, "project", before, after)["items"][0][
            "classifications"
        ]
    )
    monkeypatch.setattr(comparison, "reachable_states", lambda *args: {})
    with pytest.raises(ValueError, match="committed product history"):
        comparison.compare_states(journal, "project", before, after)
    assert len(calls) == 1


def test_failed_derivation_is_retried_not_cached(tmp_path, monkeypatch):
    journal = Journal(tmp_path / "journal")
    state = seed(journal)
    original = comparison._compare_states
    calls = []

    def fail(*args):
        calls.append(1)
        raise RuntimeError("Failed derivation")

    monkeypatch.setattr(comparison, "_compare_states", fail)
    for _ in range(2):
        with pytest.raises(RuntimeError, match="Failed derivation"):
            comparison.compare_states(journal, "project", state, state)
    assert len(calls) == 2
    monkeypatch.setattr(comparison, "_compare_states", original)
    assert comparison.compare_states(journal, "project", state, state)["total"] == 0
