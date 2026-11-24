"""A mapping entry matches a component by the package name its package URL
names when nothing matches its own name (a BOM may name a component
differently from its package)."""

from dtvp.logic import BOMAnalysisCache
from dtvp.team_mapping import get_team_mapping_tags

MAPPING = {
    "vp-stats-app": "Core",
    "org.keycloak:keycloak-core": "Identity",
    "@scope/widget": "Web",
    "*": "Unknown",
}


def tags(name, purl, group=None, *, wildcard=True):
    return get_team_mapping_tags(
        MAPPING, name, group, purl, group_known=True, include_wildcard=wildcard
    )


def test_package_name_from_the_purl_matches_when_the_name_does_not():
    assert tags("stats-app", "pkg:npm/vp-stats-app@0.1.2") == ("Core",)


def test_namespace_from_the_purl_is_the_group():
    assert tags("Keycloak Core", "pkg:maven/org.keycloak/keycloak-core@26.0.5?type=jar") == (
        "Identity",
    )
    assert tags("widget-ui", "pkg:npm/%40scope/widget@1.0.0") == ("Web",)


def test_a_name_only_entry_does_not_match_a_namespaced_package():
    assert tags("x", "pkg:maven/org.other/vp-stats-app@1") == ("Unknown",)


def test_the_own_name_wins_over_the_package_name():
    mapping = {"stats-app": "Phoenix", "vp-stats-app": "Core"}
    assert get_team_mapping_tags(
        mapping, "stats-app", None, "pkg:npm/vp-stats-app@0.1.2", group_known=True
    ) == ("Phoenix",)


def test_without_a_purl_or_any_match_the_wildcard_still_applies():
    assert tags("stats-app", None) == ("Unknown",)
    assert tags("stats-app", "pkg:npm/other@1") == ("Unknown",)
    assert tags("stats-app", "pkg:npm/other@1", wildcard=False) == ()


def _bom(root_name, root_purl):
    root = {"bom-ref": "root", "name": root_name}
    if root_purl:
        root["purl"] = root_purl
    return {
        "metadata": {"component": root},
        "components": [
            {"bom-ref": "tar", "name": "tar", "version": "2.2.2", "purl": "pkg:npm/tar@2.2.2"},
            {"bom-ref": "gyp", "name": "node-gyp", "version": "3.8.0", "purl": "pkg:npm/node-gyp@3.8.0"},
        ],
        "dependencies": [
            {"ref": "root", "dependsOn": ["gyp"]},
            {"ref": "gyp", "dependsOn": ["tar"]},
        ],
    }


def test_a_bom_root_named_unlike_its_package_owns_its_chain():
    # A standalone project: the BOM calls its root "stats-app", its package
    # URL names vp-stats-app, which the mapping assigns to Core.
    cache = BOMAnalysisCache(_bom("stats-app", "pkg:npm/vp-stats-app@0.1.2"), MAPPING)
    assert cache.get_tags_only("tar", "tar", "pkg:npm/tar@2.2.2") == ["Core"]


def test_a_chain_without_any_mapped_name_or_package_falls_to_the_wildcard():
    cache = BOMAnalysisCache(_bom("stats-app", None), MAPPING)
    assert cache.get_tags_only("tar", "tar", "pkg:npm/tar@2.2.2") == ["Unknown"]
