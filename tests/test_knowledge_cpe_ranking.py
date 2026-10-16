"""Local compatibility cases adapted from sibling cpeservice's mapping audit."""

import copy

import pytest

from dtvp.knowledge.cpe_ranking import rank_candidates


def cpe(vendor, product, target="*", version="*", part="a"):
    return f"cpe:2.3:{part}:{vendor}:{product}:{version}:*:*:*:*:{target}:*:*"


def record(value, *refs, **changes):
    return {
        "cpeName": value,
        "source": "supplied-nvd",
        "publisher": "NVD",
        "refs": [{"ref": ref} for ref in refs],
        **changes,
    }


def component(purl="pkg:npm/less@4"):
    return {
        "bom-ref": "occurrence",
        "purl": purl,
        "externalReferences": [{"type": "vcs", "url": "https://github.com/less/less.js"}],
    }


def test_less_homonym_uses_supplied_source_and_retains_provenance_not_approval():
    records = [
        record(cpe("gnu", "less"), "https://github.com/gnu/less"),
        record(cpe("lesscss", "less"), "https://github.com/less/less.js/releases"),
    ]
    original = copy.deepcopy(records)
    result = rank_candidates(component(), records)
    assert [row["cpe"] for row in result["candidates"]] == [cpe("lesscss", "less")]
    assert result["rejected"][0]["rejection"] == "conflicting_supplied_repository_claims"
    assert result["selection"] is None and result["applicability"] == "not_assessed"
    assert result["candidates"][0]["record"]["publisher"] == "NVD"
    assert "confidence" not in result["candidates"][0]
    assert result["candidates"][0]["cpe"].split(":")[5] == "*"  # No invented version.
    assert records == original


def test_exact_registry_coordinate_preserves_scoped_namespace_and_qualifiers():
    comp = component("pkg:npm/%40babel/core@7?arch=x64#lib")
    records = [
        record(cpe("babel", "core"), "https://www.npmjs.com/package/@babel/core"),
        record(cpe("other", "core"), "https://npmjs.com/package/core"),
    ]
    result = rank_candidates(comp, records)
    assert [row["cpe"] for row in result["candidates"]] == [cpe("babel", "core")]
    assert "arch=x64#lib" in result["requested_purl"]


@pytest.mark.parametrize(
    "purl,value",
    [
        ("pkg:npm/uuid", cpe("satori", "uuid", "go")),
        ("pkg:npm/%40types/express", cpe("expressjs", "express", "node.js")),
        ("pkg:pypi/multipart", cpe("kong", "multipart", "lua")),
        ("pkg:npm/winston", cpe("vendor", "winston", part="h")),
    ],
)
def test_ecosystem_and_types_cannot_be_overridden_by_exact_registry_or_mapping(purl, value):
    comp = component(purl)
    result = rank_candidates(
        comp, [record(value)], [{"purl": purl, "cpe": value, "source": "mapping"}]
    )
    assert not result["candidates"]
    assert result["rejected"][0]["rejection"] == "incompatible_part_or_ecosystem"


def test_vendor_without_product_and_shared_monorepo_do_not_establish_identity():
    comp = component("pkg:npm/%40angular/zone.js@1")
    comp["externalReferences"][0]["url"] = "https://github.com/angular/angular"
    result = rank_candidates(
        comp, [record(cpe("angular", "angular"), "https://github.com/angular/angular")]
    )
    assert result["rejected"][0]["rejection"] == "insufficient_package_identity_evidence"


def test_ties_abstain_and_deprecated_malformed_or_other_versions_cannot_win():
    refs = "https://npmjs.com/package/foo"
    records = [
        record(cpe("a", "foo"), refs),
        record(cpe("b", "foo"), refs),
        record(cpe("c", "foo"), refs, deprecated=True),
        record("bad", refs),
        record(cpe("v", "foo", version="2"), refs),
    ]
    result = rank_candidates(component("pkg:npm/foo@1"), records)
    assert result["ambiguity"] == "cross_identity_tie" and result["selection"] is None
    assert result["counts"] == {"supplied": 5, "candidates": 2, "rejected": 3}
    assert (
        result["content_digest"]
        == rank_candidates(component("pkg:npm/foo@1"), records, offset=1, limit=1)["content_digest"]
    )


def test_explicit_alias_policy_reused_without_changing_existing_discovery():
    rule = {
        "pkg:npm/alias": {
            "target_purl": "pkg:npm/foo",
            "source": "curator",
            "reason": "Reviewed alias",
        }
    }
    result = rank_candidates(
        component("pkg:npm/alias@1"),
        [record(cpe("vendor", "foo"), "https://npmjs.com/package/foo")],
        rules=rule,
    )
    assert result["resolved_purl"] == "pkg:npm/foo@1" and result["counts"]["candidates"] == 1
    assert result["policy_proposal"]["reviewed_rules"][0]["reason"] == "Reviewed alias"


def test_host_spoof_credentials_and_resource_bounds_fail_closed():
    comp = component("pkg:npm/foo")
    for ref in [
        "https://npmjs.com.attacker/package/foo",
        "https://npmjs.com@attacker/package/foo",
        "https://user:pass@npmjs.com/package/foo",
    ]:
        assert not rank_candidates(comp, [record(cpe("a", "foo"), ref)])["candidates"]
    with pytest.raises(ValueError):
        rank_candidates(comp, [record(cpe("a", "foo"))] * 2001)
    with pytest.raises(ValueError):
        rank_candidates(comp, [record(cpe("a", "foo"), deprecated="false")])
    with pytest.raises(ValueError):
        rank_candidates(comp, [record(cpe("a", "foo"), *("x" * 2048 for _ in range(51)))])


def test_dictionary_bindings_and_constraints_are_retained_not_generalized():
    value = "cpe:/a:vendor:foo:1"
    result = rank_candidates(
        component("pkg:npm/foo@1"), [record(value, "https://npmjs.com/package/foo")]
    )
    assert result["candidates"][0]["cpe"] == value
    denied = rank_candidates(
        component("pkg:npm/foo@1"),
        [record(cpe("vendor", "foo", version="-"), "https://npmjs.com/package/foo")],
    )
    assert not denied["candidates"]
    assert (
        denied["rejected"][0]["rejection"] == "explicit_cpe_version_conflicts_with_package_version"
    )
    result["limitations"].clear()
    assert rank_candidates(component("pkg:npm/foo@1"), [record(value)])["limitations"]


def test_unknown_package_version_never_claims_concrete_dictionary_version_match():
    result = rank_candidates(
        component("pkg:npm/foo"),
        [record(cpe("a", "foo", version="1"), "https://npmjs.com/package/foo")],
    )
    assert result["candidates"][0]["version_comparison"] == "component_version_unknown"
    assert result["candidates"][0]["cpe"] == cpe("a", "foo", version="1")
    known = rank_candidates(
        component("pkg:npm/foo@1"), [record(cpe("a", "foo"), "https://npmjs.com/package/foo")]
    )
    assert known["candidates"][0]["version_comparison"] == "catalog_version_unspecified"
