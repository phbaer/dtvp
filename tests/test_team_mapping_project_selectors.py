"""Project selectors (``project::<project>``, ``project:<project>::<selector>``),
key validation, and the precedence of the matcher. The parse and match cases
are shared with the browser matcher (frontend vitest
``team-mapping-shared-cases.spec.ts``) through
``tests/fixtures/team_mapping_cases.json``."""

import json
from pathlib import Path

import pytest

from dtvp.logic import BOMAnalysisCache, group_vulnerabilities
from dtvp.settings_files import validate_settings_document
from dtvp.team_mapping import (
    ComponentIdentity,
    find_team_mapping_match,
    parse_team_mapping_key,
    team_mapping_key_errors,
)

CASES = json.loads(
    (Path(__file__).parent / "fixtures" / "team_mapping_cases.json").read_text()
)

FIELDS = {
    "name": "name",
    "group": "group",
    "purl": "purl",
    "project": "project",
    "projectFallback": "project_fallback",
    "caseSensitive": "case_sensitive",
    "requireNoGroup": "require_no_group",
    "wildcard": "wildcard",
}


@pytest.mark.parametrize("case", CASES["parse"], ids=lambda case: case["key"] or "<empty>")
def test_parse_shared_cases(case):
    selector = parse_team_mapping_key(case["key"])
    if "error" in case:
        assert selector.error == case["error"]
        return
    assert selector.error is None
    for field, expected in case["expect"].items():
        assert getattr(selector, FIELDS[field]) == expected, field


MATCH_CASES = [
    (group["mapping"], case, f"{group['name']}: {case['identity']} in {case['project']}")
    for group in CASES["match"]
    for case in group["cases"]
]


@pytest.mark.parametrize("mapping,case,label", MATCH_CASES, ids=[item[2] for item in MATCH_CASES])
def test_match_shared_cases(mapping, case, label):
    identity = case["identity"]
    match = find_team_mapping_match(
        mapping,
        ComponentIdentity(
            name=identity.get("name") or "",
            group=identity.get("group"),
            purl=identity.get("purl"),
            group_known=bool(identity.get("groupKnown")),
        ),
        include_wildcard=case["wildcard"],
        project=case["project"],
    )
    assert (match.key if match else None) == case["expect"], label


def test_key_errors_name_every_invalid_key():
    assert team_mapping_key_errors({"core": "A", "foo::bar": "B", "project::": "C"}) == [
        "Mapping key 'foo::bar': Unknown modifier 'foo' before '::'",
        "Mapping key 'project::': 'project::' needs a project name",
    ]
    assert team_mapping_key_errors({"project::P": "A", "project:P::core": "B", "*": "C"}) == []


def test_saving_rejects_invalid_keys():
    errors = validate_settings_document("team_mapping", {"cs,ci::core": "A"})
    assert errors == ["Mapping key 'cs,ci::core': Modifiers cs and ci contradict each other"]
    assert validate_settings_document("team_mapping", {"project::P": "A"}) == []


def test_put_mapping_with_an_invalid_key_is_refused(client, tmp_path):
    from unittest.mock import patch

    from dtvp import main

    main.app.dependency_overrides[main.get_current_user] = lambda: "reviewer"
    target = tmp_path / "mapping.json"
    try:
        with patch("dtvp.main.get_team_mapping_path", return_value=str(target)), patch(
            "dtvp.main.get_user_role", return_value="REVIEWER"
        ):
            response = client.put("/api/settings/mapping", json={"nope::core": "A"})
    finally:
        main.app.dependency_overrides = {}
    assert response.json()["status"] == "error"
    assert "Unknown modifier 'nope'" in response.json()["message"]
    assert not target.exists()


def test_an_invalid_stored_key_still_matches_as_before():
    # Stored before validation existed: the unknown modifier part is read
    # as part of the selector, as it always was.
    selector = parse_team_mapping_key("foo::bar")
    assert (selector.group, selector.name) == ("foo", ":bar")


# -- the BOM walk --------------------------------------------------------

MAPPING = {
    "project:ViewPoint_Product::core": "VP Core",
    "project::eventserver": "Events",
    "*": "Unknown",
}


def _bom(root, children, edges):
    return {
        "metadata": {"component": {"bom-ref": "root", "name": root}},
        "components": [{"bom-ref": ref, "name": name} for ref, name in children],
        "dependencies": [{"ref": ref, "dependsOn": deps} for ref, deps in edges],
    }


VP_BOM = _bom(
    "ViewPoint_Product",
    [("core", "core"), ("zlib", "zlib"), ("tiff", "libtiff")],
    [("root", ["core", "tiff"]), ("core", ["zlib"])],
)


def test_a_project_scoped_selector_owns_its_subtree_only_in_its_project():
    cache = BOMAnalysisCache(VP_BOM, MAPPING, "ViewPoint_Product")
    assert cache.get_tags_only("zlib", "zlib") == ["VP Core"]
    assert cache.get_owner_mapping_keys("zlib", "zlib") == ["project:ViewPoint_Product::core"]
    assert cache.get_tags_only("tiff", "libtiff") == ["Unknown"]

    other = BOMAnalysisCache(VP_BOM, MAPPING, "Another_Product")
    assert other.get_tags_only("zlib", "zlib") == ["Unknown"]


def test_the_project_name_defaults_to_the_bom_root():
    cache = BOMAnalysisCache(VP_BOM, MAPPING)
    assert cache.project_name == "ViewPoint_Product"
    assert cache.get_tags_only("zlib", "zlib") == ["VP Core"]


def test_project_fallback_owns_what_no_component_owns_and_ranks_below_components():
    bom = _bom(
        "eventserver",
        [("lib", "lib"), ("core", "core")],
        [("root", ["lib", "core"])],
    )
    mapping = {**MAPPING, "core": "Generic Core"}
    cache = BOMAnalysisCache(bom, mapping, "eventserver")
    assert cache.get_tags_only("lib", "lib") == ["Events"]
    assert cache.get_owner_mapping_keys("lib", "lib") == ["project::eventserver"]
    assert cache.resolve_owner("lib", "lib")[0] == "project"
    assert cache.get_tags_only("core", "core") == ["Generic Core"]
    assert cache.resolve_owner("core", "core")[0] == "component"
    # A project fallback does not stop the walk: it is not a mapped
    # component, so a component below still reaches a mapped ancestor.
    assert not cache._is_team_mapped_ref("root")


def test_resolve_owner_kinds():
    cache = BOMAnalysisCache(VP_BOM, {"zlib": "Z", "*": "Unknown"}, "ViewPoint_Product")
    assert cache.resolve_owner("zlib", "zlib") == ("component", ["Z"], "zlib")
    assert cache.resolve_owner("tiff", "libtiff") == ("wildcard", ["Unknown"], "tiff")
    bare = BOMAnalysisCache(VP_BOM, {"zlib": "Z"}, "ViewPoint_Product")
    assert bare.resolve_owner("tiff", "libtiff") == ("none", [], "tiff")


def test_grouping_passes_the_project_name_to_the_matcher(monkeypatch):
    monkeypatch.setattr("dtvp.logic.load_team_mapping", lambda: MAPPING)
    finding = {
        "component": {"uuid": "zlib", "name": "zlib", "version": "1"},
        "vulnerability": {"vulnId": "CVE-2026-0001", "severity": "HIGH"},
        "analysis": {},
    }
    versions = [
        {
            "version": {"uuid": "v1", "name": "ViewPoint_Product", "version": "1.0"},
            "vulnerabilities": [finding],
        }
    ]
    # The BOM's root is named differently: the project name given wins.
    bom = {**VP_BOM, "metadata": {"component": {"bom-ref": "root", "name": "vp-root"}}}
    groups = group_vulnerabilities(versions, project_boms={"v1": bom})
    assert groups[0]["tags"] == ["VP Core"]
