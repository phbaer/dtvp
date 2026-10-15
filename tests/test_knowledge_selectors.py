"""V1 selector parity and normalized-component namespace evidence."""

import pytest

from dtvp.knowledge.selectors import (
    ComponentIdentity,
    compile_team_mapping,
    component_identity,
    find_team_mapping_match,
    get_primary_team_for_identity,
    normalize_team_values,
    parse_team_mapping_key,
    primary_team,
    selector_matches_identity,
)


@pytest.mark.parametrize(
    ("component", "expected"),
    [
        ({"name": "core"}, ComponentIdentity("core")),
        ({"name": "core", "group": ""}, ComponentIdentity("core", group_known=True)),
        (
            {"name": "core", "group": "@angular"},
            ComponentIdentity("core", "@angular", group_known=True),
        ),
        (
            {"name": "friendly", "purl": "pkg:npm/%40angular/core@1.2.3"},
            ComponentIdentity("core", "@angular", "pkg:npm/%40angular/core@1.2.3", True),
        ),
        (
            {"name": "friendly", "purl": "pkg:pypi/core@1.2.3"},
            ComponentIdentity("core", None, "pkg:pypi/core@1.2.3", True),
        ),
        (
            {"name": "friendly", "group": "", "purl": "pkg:maven/org/core@1"},
            ComponentIdentity("friendly", None, "pkg:maven/org/core@1", True),
        ),
        (
            {"component_name": "core", "component_group": None},
            ComponentIdentity("core", group_known=True),
        ),
        (
            {"name": "core", "purl": "invalid"},
            ComponentIdentity("core", purl="invalid"),
        ),
    ],
)
def test_component_identity_preserves_namespace_evidence(component, expected):
    assert component_identity(component) == expected


@pytest.mark.parametrize(
    ("selector", "identity", "matches"),
    [
        ("core", ComponentIdentity("core"), True),
        ("core", ComponentIdentity("core", "@angular", group_known=True), False),
        ("cs::Core", ComponentIdentity("core"), False),
        ("cs::Core", ComponentIdentity("Core"), True),
        ("nogroup::core", ComponentIdentity("core"), False),
        ("nogroup::core", ComponentIdentity("core", group_known=True), True),
        ("nogroup::core", ComponentIdentity("core", "@angular", group_known=True), False),
        ("@angular:core", ComponentIdentity("CORE", "@Angular", group_known=True), True),
        ("@angular/core", ComponentIdentity("core", "@angular", group_known=True), True),
        ("cs:core", ComponentIdentity("core", "cs", group_known=True), True),
        ("nogroup:core", ComponentIdentity("core", "nogroup", group_known=True), True),
        ("cs+nogroup::Core", ComponentIdentity("Core", group_known=True), True),
        ("case_sensitive,no_group::Core", ComponentIdentity("core", group_known=True), False),
    ],
)
def test_v1_name_namespace_case_selectors(selector, identity, matches):
    assert selector_matches_identity(parse_team_mapping_key(selector), identity) is matches


def test_v1_specificity_case_and_deterministic_ties():
    identity = ComponentIdentity("Core", group_known=True)
    assert find_team_mapping_match({"core": "Lower", "Core": "Exact"}, identity).value == "Exact"
    assert find_team_mapping_match(
        {"core": "Name", "nogroup::core": "Known", "cs::Core": "Case"}, identity
    ).value == "Known"
    assert find_team_mapping_match({"core": "Name", "cs::Core": "Case"}, identity).value == "Case"
    # Neither is exact case; insertion order must not decide the owner.
    assert find_team_mapping_match({"core": "Lower", "CORE": "Upper"}, identity).value == "Upper"
    assert find_team_mapping_match({"CORE": "Upper", "core": "Lower"}, identity).value == "Upper"


@pytest.mark.parametrize(
    ("key", "purl", "matches"),
    [
        ("purl::pkg:maven/org.example/core", "pkg:maven/org.example/core@1.2.3", True),
        (
            "purl::pkg:maven/org.example/core",
            "pkg:maven/org.example/core@1.2.3?type=jar#src",
            True,
        ),
        ("purl::pkg:maven/org.example/core@9.9.9", "pkg:maven/org.example/core@1.2.3", False),
        ("purl::pkg:maven/org.example/core@1.2.3", "pkg:maven/org.example/core@1.2.3", True),
        (
            "purl::pkg:maven/org.example/core@1.2.3",
            "pkg:maven/org.example/core@1.2.3?type=jar",
            False,
        ),
        ("cs,purl::pkg:maven/org.example/core", "pkg:maven/org.example/Core@1.2.3", False),
        ("package-url::pkg:npm/%40scope/core", "pkg:npm/%40scope/core@1", True),
    ],
)
def test_v1_purl_versions_qualifiers_and_modifiers(key, purl, matches):
    identity = ComponentIdentity("ignored", purl=purl)
    assert selector_matches_identity(parse_team_mapping_key(key), identity) is matches


def test_v1_purl_selector_wins_over_namespace_selector():
    identity = ComponentIdentity("core", "@angular", "pkg:maven/org.example/core@1.2.3", True)
    match = find_team_mapping_match(
        {"@angular:core": "Angular", "purl::pkg:maven/org.example/core": "Platform"}, identity
    )
    assert match.value == "Platform"


def test_aliases_are_preserved_with_one_primary_team_and_opt_in_fallback():
    mapping = {"core": [" Platform ", "PLT", "Platform", "", None], "*": "Fallback"}
    compiled = compile_team_mapping(mapping)
    assert compile_team_mapping(compiled) is compiled
    match = find_team_mapping_match(compiled, ComponentIdentity("core"), include_wildcard=True)
    assert match.tags == ("Platform", "PLT")
    assert primary_team(match.value) == "Platform"
    assert normalize_team_values(None) == ()
    assert find_team_mapping_match(compiled, ComponentIdentity("other")) is None
    assert get_primary_team_for_identity(mapping, "other", include_wildcard=True) == "Fallback"
    assert find_team_mapping_match({"core": []}, ComponentIdentity("core")) is None
