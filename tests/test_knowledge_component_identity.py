from copy import deepcopy

import pytest

from dtvp.knowledge.component_identity import markers, reconcile_components


def package(**changes):
    return {
        "type": "library",
        "name": "Thing",
        "version": "1.0",
        "purl": "pkg:generic/Thing@1.0",
        **changes,
    }


def matched(old, new):
    return reconcile_components({"old": old}, {"new": new})["pairs"]


def test_full_purl_exact_identity_and_case_preservation():
    value = package(purl="pkg:generic/Thing@1.0?arch=x86_64#module")
    assert markers(value)["exact_key"] == value["purl"]
    assert matched(value, deepcopy(value)) == [
        {"previous_ref": "old", "current_ref": "new", "basis": "exact_purl"}
    ]
    assert not matched(value, package(purl="pkg:generic/Thing@1.0?arch=aarch64#module"))
    assert not matched(value, package(purl="pkg:generic/thing@1.0?arch=x86_64#module"))


def test_versionless_purl_is_only_family_marker():
    item = markers(package(purl="pkg:generic/Thing"))
    assert item["family_key"] == "pkg:generic/Thing"
    assert item["exact_key"] is None
    assert not matched(package(purl="pkg:generic/Thing"), package(purl="pkg:generic/Thing"))


@pytest.mark.parametrize(
    "changes",
    [{"version": "2.0"}, {"purl": "pkg:generic/Thing@2.0", "version": "2.0"}, {"group": "other"}],
)
def test_declared_strong_conflicts_block_match(changes):
    assert not matched(package(group="original"), package(**{"group": "original", **changes}))


def test_scoped_hash_requires_exact_known_type_name_version():
    base = package(purl=None, hashes=[{"alg": "SHA256", "content": "A" * 64}])
    assert matched(base, deepcopy(base))[0]["basis"] == "scoped_strong_digest"
    for field in ("type", "name", "version"):
        changed = {**base, field: None}
        assert not matched(changed, changed)
    assert not matched(base, {**base, "name": "Other"})
    assert not matched(base, {**base, "version": "2.0"})


@pytest.mark.parametrize("bad", [123, "not-a-purl", "pkg:generic/Thing@2.0"])
def test_bad_purl_cannot_downgrade_to_matching_digest(bad):
    base = package(hashes=[{"alg": "SHA-256", "content": "a" * 64}])
    assert not matched(base, {**base, "purl": bad})


def test_hash_conflicts_veto_same_purl_and_aliases_normalize():
    base = package(hashes=[{"alg": "SHA256", "content": "A" * 64}])
    assert markers(base)["strong_hashes"] == {"SHA-256": "a" * 64}
    assert not matched(base, package(hashes=[{"alg": "SHA-256", "content": "b" * 64}]))
    assert not matched(
        base, package(hashes=base["hashes"] + [{"alg": "SHA-256", "content": "b" * 64}])
    )
    assert matched(base, package())  # Missing hash is not a contradictory assertion.
    assert matched(base, deepcopy(base))[0]["basis"] == "exact_purl"


@pytest.mark.parametrize("bad", [None, {}, [None], [{"alg": "SHA-256", "content": "short"}]])
def test_malformed_optional_hash_evidence_is_diagnostic_not_exception(bad):
    value = markers(package(hashes=bad))
    assert value["conflicts"]
    assert not matched(package(), package(hashes=bad))


def test_weak_hash_or_name_cpe_alone_does_not_match():
    for fields in (
        {},
        {"cpe": "cpe:2.3:a:vendor:name:*:*:*:*:*:*:*:*"},
        {"hashes": [{"alg": "MD5", "content": "a" * 32}]},
    ):
        base = package(purl=None, **fields)
        assert not matched(base, base)


def test_duplicate_occurrences_never_collapse_even_when_one_conflicts():
    previous = {"a": package(), "b": package(version="wrong")}
    result = reconcile_components(previous, {"new": package()})
    assert result["pairs"] == []
    assert result["unresolved"][0]["reason"] == "ambiguous_occurrences"
    assert not reconcile_components({"old": package()}, {"x": package(), "y": package()})["pairs"]


def test_same_source_ref_does_not_establish_portable_identity():
    item = package(purl=None)
    assert not reconcile_components({"same": item}, {"same": item})["pairs"]


def test_large_duplicate_bucket_has_bounded_diagnostics():
    result = reconcile_components(
        {str(i): package() for i in range(3000)}, {str(i): package() for i in range(3000)}
    )
    assert not result["pairs"]
    assert result["summary"]["unresolved"] == 3000
    assert len(result["unresolved"]) == 200
    assert result["diagnostics_truncated"]


def test_inputs_unchanged_and_deterministic():
    old, new = {"a": package()}, {"b": package()}
    original = deepcopy([old, new])
    assert reconcile_components(old, new) == reconcile_components(old, new)
    assert [old, new] == original


def test_conflicting_marker_reason_dominates_ambiguous_buckets_deterministically():
    hashes = [
        {"alg": algorithm, "content": "a" * length}
        for algorithm, length in (("SHA-256", 64), ("SHA-384", 96), ("SHA-512", 128))
    ]
    previous = {
        "same-a": package(),
        "same-b": package(),
        "conflicting": package(purl="pkg:generic/Different@1.0", hashes=hashes),
    }
    current = {"new": package(hashes=hashes)}
    expected = reconcile_components(previous, current)
    assert not expected["pairs"]
    assert expected["unresolved"][0]["reason"] == "conflicting_identity_markers"
    assert reconcile_components(dict(reversed(list(previous.items()))), current) == expected
