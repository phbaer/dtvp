"""The fixed version of a finding, from the ranges Dependency-Track holds."""

import pytest

from dtvp.fixed_versions import (
    Fix,
    compare_versions,
    derive_recommendation,
    display_name,
    fix_for,
    matching_entries,
    recommendation_text,
    slim_affected_components,
)

# -- Dependency-Track's version comparison ------------------------------------


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("1.2.3", "1.2.10", -1),  # numbers, not text
        ("1.2.10", "1.2.3", 1),
        ("1.2.3", "1.2.3", 0),
        ("1.0.0", "1.0.0.0", 0),  # a trailing zero part
        ("1.0", "1.0.1", -1),
        ("1.0.0-beta1", "1.0.0-rc1", -1),  # beta before rc
        ("1.0.0-rc1", "1.0.0-rc2", -1),
        # Dependency-Track ranks a pre-release above the release; the port
        # keeps that, so a range contains what it contains there.
        ("1.0.0-rc1", "1.0.0", 1),
        # The Ubuntu suffix of a deb version is not compared (DT issue 1374).
        ("1:2.3.4-1ubuntu0.1", "2.3.4", 0),
        ("2.3.4-0ubuntu1", "2.3.5", -1),
        ("4.1.42.Final", "4.1.59.Final", -1),
        # Beyond Java's int the parts are compared as text, as in DT.
        ("99999999999", "100000000000", 1),
    ],
)
def test_versions_compare_as_dependency_track_compares_them(left, right, expected):
    assert compare_versions(left, right) == expected


# -- choosing the range ---------------------------------------------------------

NPM = {"name": "lib-a", "version": "1.4.0", "purl": "pkg:npm/lib-a@1.4.0"}


def _range(identity="pkg:npm/lib-a", sources=("GITHUB",), kind="PURL", **bounds):
    return {
        "identityType": kind, "identity": identity, "versionType": "RANGE",
        **bounds, "sources": list(sources),
    }


def test_a_single_range_must_contain_the_version_too():
    # Other analyzers (OSS Index, Trivy, Snyk) report findings too, so a
    # reported finding does not say that the one range applies.
    assert fix_for(NPM, [_range(versionStartIncluding="2.0", versionEndExcluding="2.1")]) is None
    assert fix_for(NPM, [_range(versionStartIncluding="1.0", versionEndExcluding="1.5")]) == (
        Fix("1.5", (), ("GITHUB",))
    )


@pytest.mark.parametrize(
    ("component", "entries"),
    [
        # A range below the installed version and an exact entry of it.
        ({"name": "lib", "version": "2.0.0", "purl": "pkg:npm/lib@2.0.0"},
         [_range("pkg:npm/lib", versionStartIncluding="1.0", versionEndExcluding="1.5"),
          {"identityType": "PURL", "identity": "pkg:npm/lib@2.0.0", "versionType": "EXACT",
           "version": "2.0.0"}]),
        # One range below the installed version.
        ({"name": "lib-a", "version": "2.5.0", "purl": "pkg:npm/lib-a@2.5.0"},
         [_range(versionEndExcluding="2.0.0")]),
        # Another branch of a CPE.
        ({"name": "openssl", "version": "3.0.13",
          "cpe": "cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*"},
         [_range("cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*", kind="CPE",
                 versionStartIncluding="1.1.1", versionEndExcluding="1.1.1w")]),
        # Another release's range under a purl without a distro qualifier.
        ({"name": "openssl", "version": "3.0.11-1~deb12u1",
          "purl": "pkg:deb/debian/openssl@3.0.11-1~deb12u1?distro=debian-12"},
         [_range("pkg:deb/debian/openssl", versionStartIncluding="3.1.0",
                 versionEndExcluding="3.1.4-1")]),
    ],
    ids=["range-plus-exact", "below", "cpe-branch", "other-distro"],
)
def test_a_single_range_that_does_not_contain_the_version_gives_no_fix(component, entries):
    assert fix_for(component, entries) is None
    assert derive_recommendation(component, entries) is None


def test_a_single_range_without_a_version_gives_no_fix():
    entries = [_range(versionEndExcluding="2.1")]
    for version in ("", "*", "-"):
        assert fix_for({**NPM, "version": version}, entries) is None
    assert fix_for({key: value for key, value in NPM.items() if key != "version"},
                   entries) is None


def test_of_several_ranges_the_one_containing_the_version_is_chosen():
    entries = [
        _range(versionEndExcluding="1.2.3"),
        _range(versionStartIncluding="1.3.0", versionEndExcluding="1.4.2", sources=("OSV",)),
        _range(versionStartIncluding="2.0.0", versionEndExcluding="2.0.5"),
    ]
    fix = fix_for(NPM, entries)
    assert fix.version == "1.4.2"
    assert fix.sources == ("OSV",)
    assert fix.later_ranges == (">=2.0.0 <2.0.5",)
    assert recommendation_text(NPM, fix) == (
        "Upgrade lib-a 1.4.0 to 1.4.2 or later. Later versions are affected too: >=2.0.0 <2.0.5."
    )


def test_ranges_that_agree_name_every_mirror():
    entries = [
        _range(versionStartIncluding="1.0", versionEndExcluding="1.4.2", sources=("GITHUB",)),
        _range(versionStartIncluding="1.3", versionEndExcluding="1.4.2", sources=("OSV", "GITHUB")),
        _range(versionEndExcluding="0.9"),
    ]
    assert fix_for(NPM, entries).sources == ("GITHUB", "OSV")


def test_containing_ranges_with_differing_ends_give_no_fix():
    entries = [
        _range(versionStartIncluding="1.0", versionEndExcluding="1.4.2"),
        _range(versionStartIncluding="1.3", versionEndExcluding="1.5.0"),
    ]
    assert fix_for(NPM, entries) is None


@pytest.mark.parametrize(
    "entries",
    [
        [_range(versionEndIncluding="1.4.0")],  # the end is affected: no fix known
        [_range(versionStartIncluding="1.0")],  # open end
        [{"identityType": "PURL", "identity": "pkg:npm/lib-a", "versionType": "EXACT",
          "version": "1.4.0"}],
        [],
    ],
    ids=["end-including", "open-end", "exact-only", "none"],
)
def test_without_an_excluded_end_there_is_no_fix(entries):
    assert fix_for(NPM, entries) is None
    assert derive_recommendation(NPM, entries) is None


def test_no_containing_range_gives_no_fix():
    entries = [_range(versionEndExcluding="1.0"), _range(versionStartIncluding="2.0",
                                                          versionEndExcluding="2.1")]
    assert fix_for(NPM, entries) is None
    # Without a version nothing can be compared.
    assert fix_for({**NPM, "version": ""}, entries) is None


def test_a_fixed_version_another_range_affects_moves_to_its_end():
    lib = {"name": "lib", "version": "1.2.0", "purl": "pkg:npm/lib@1.2.0"}
    below = _range("pkg:npm/lib", versionEndExcluding="2.0")
    overlapping = _range("pkg:npm/lib", versionStartIncluding="1.8",
                         versionEndExcluding="2.1", sources=("OSV",))
    fix = fix_for(lib, [below, overlapping])
    assert fix == Fix("2.1", (), ("GITHUB", "OSV"))
    # Overlapping again: moved once more.
    further = _range("pkg:npm/lib", versionStartIncluding="2.1", versionEndExcluding="2.3")
    assert fix_for(lib, [below, overlapping, further]).version == "2.3"
    # An overlapping range without an excluded end: no fix.
    open_end = _range("pkg:npm/lib", versionStartIncluding="1.9")
    assert fix_for(lib, [below, open_end]) is None
    including = _range("pkg:npm/lib", versionStartIncluding="1.9", versionEndIncluding="2.4")
    assert fix_for(lib, [below, including]) is None


def _exact(version, identity="pkg:npm/lib"):
    return {"identityType": "PURL", "identity": identity, "versionType": "EXACT",
            "version": version}


def test_exact_versions_at_or_above_the_fix_are_affected_or_named():
    lib = {"name": "lib", "version": "1.2.0", "purl": "pkg:npm/lib@1.2.0"}
    below = _range("pkg:npm/lib", versionEndExcluding="2.0")
    # The fixed version itself is listed as affected: no fix.
    assert fix_for(lib, [below, _exact("2.0")]) is None
    assert fix_for(lib, [below, _exact("2.0.0")]) is None  # 2.0 equals 2.0.0
    # A later exact version is named, in order with the later ranges.
    later = _range("pkg:npm/lib", versionStartIncluding="2.5", versionEndExcluding="2.6")
    fix = fix_for(lib, [below, _exact("3.1"), later, _exact("1.0"), _exact("2.2")])
    assert fix.version == "2.0"
    assert fix.later_ranges == ("2.2", ">=2.5 <2.6", "3.1")
    assert recommendation_text(lib, fix) == (
        "Upgrade lib 1.2.0 to 2.0 or later. Later versions are affected too: 2.2, >=2.5 <2.6, 3.1."
    )


# -- identities -----------------------------------------------------------------


def test_a_distro_qualifier_must_match_when_both_have_one():
    component = {
        "name": "openssl", "version": "3.0.2-0ubuntu1.10",
        "purl": "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10?arch=amd64&distro=ubuntu-22.04",
    }
    jammy = _range("pkg:deb/ubuntu/openssl?distro=ubuntu-22.04",
                   versionEndExcluding="3.0.2-0ubuntu1.12")
    focal = _range("pkg:deb/ubuntu/openssl?distro=ubuntu-20.04",
                   versionEndExcluding="1.1.1f-1ubuntu2.20")
    any_distro = _range("pkg:deb/ubuntu/openssl", versionEndExcluding="3.0.2-0ubuntu1.12")
    assert matching_entries(component, [jammy, focal, any_distro]) == [jammy, any_distro]
    assert fix_for(
        {**component, "version": "3.0.1-0ubuntu1.10"}, [jammy, focal]
    ).version == "3.0.2-0ubuntu1.12"
    # Dependency-Track does not compare the Ubuntu suffix: 3.0.2-0ubuntu1.10
    # is not below 3.0.2-0ubuntu1.12 there, so that range does not contain it.
    assert fix_for(component, [jammy, focal]) is None


def test_cpe_entries_match_by_vendor_and_product():
    component = {
        "name": "openssl", "version": "3.0.1",
        "cpe": "cpe:2.3:a:openssl:openssl:3.0.1:*:*:*:*:*:*:*",
    }
    nvd = _range("cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*", kind="CPE", sources=("NVD",),
                 versionStartIncluding="3.0.0", versionEndExcluding="3.0.2")
    old = _range("cpe:/a:openssl:openssl", kind="CPE", versionEndExcluding="1.1.1")
    other = _range("cpe:2.3:a:other:openssl:*:*:*:*:*:*:*:*", kind="CPE",
                   versionEndExcluding="9")
    assert matching_entries(component, [nvd, old, other]) == [nvd, old]
    assert fix_for(component, [nvd, old, other]) == Fix("3.0.2", (), ("NVD",))


def test_cpe_entries_for_other_software_or_parts_are_not_matched():
    joomla = {"name": "prod", "version": "2.5",
              "cpe": "cpe:2.3:a:vendor:prod:2.5:*:*:*:*:joomla:*:*"}
    for_joomla = _range("cpe:2.3:a:vendor:prod:*:*:*:*:*:joomla:*:*", kind="CPE",
                        versionEndExcluding="2.0")
    for_wordpress = _range("cpe:2.3:a:vendor:prod:*:*:*:*:*:wordpress:*:*", kind="CPE",
                           versionEndExcluding="3.0")
    any_software = _range("cpe:2.3:a:vendor:prod:*:*:*:*:*:*:*:*", kind="CPE",
                          versionEndExcluding="3.0")
    assert matching_entries(joomla, [for_joomla, for_wordpress, any_software]) == [
        for_joomla, any_software
    ]
    assert fix_for(joomla, [for_joomla, for_wordpress]) is None
    assert fix_for(joomla, [for_wordpress]) is None
    assert fix_for(joomla, [any_software]).version == "3.0"
    # Another part: an operating system is not the application.
    system = {**joomla, "cpe": "cpe:2.3:o:vendor:prod:2.5:*:*:*:*:*:*:*"}
    assert fix_for(system, [any_software]) is None
    # A component without target software matches any.
    plain = {**joomla, "cpe": "cpe:2.3:a:vendor:prod:2.5:*:*:*:*:*:*:*"}
    assert fix_for(plain, [for_wordpress]).version == "3.0"


def test_another_package_is_not_matched():
    assert fix_for(NPM, [_range("pkg:npm/lib-b", versionEndExcluding="9")]) is None
    assert fix_for(NPM, [_range("pkg:pypi/lib-a", versionEndExcluding="9")]) is None
    # Neither a package URL nor a CPE: nothing to match.
    assert fix_for({"name": "lib-a", "version": "1"}, [_range(versionEndExcluding="9")]) is None


def test_maven_names_are_case_sensitive_and_others_are_not():
    maven = {"group": "org.Acme", "name": "Core", "version": "1.0",
             "purl": "pkg:maven/org.Acme/Core@1.0"}
    assert fix_for(maven, [_range("pkg:maven/org.acme/core", versionEndExcluding="2")]) is None
    assert fix_for(maven, [_range("pkg:maven/org.Acme/Core", versionEndExcluding="2")])
    assert fix_for(NPM, [_range("pkg:npm/LIB-A", versionEndExcluding="2")]).version == "2"


# -- the text -------------------------------------------------------------------


def test_display_names():
    assert display_name({"group": "org.apache.logging.log4j", "name": "log4j-core",
                         "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0"}
                        ) == "org.apache.logging.log4j:log4j-core"
    assert display_name({"group": "@scope", "name": "name",
                         "purl": "pkg:npm/%40scope/name@1.0"}) == "@scope/name"
    # The group from the package URL when the component has none.
    assert display_name({"name": "name", "purl": "pkg:npm/%40scope/name@1.0"}) == "@scope/name"
    assert display_name(NPM) == "lib-a"
    # The package URL names the installed package; the component's name may
    # be a product name.
    assert display_name({"name": "sqlite", "purl": "pkg:pypi/sqlite3@3.50.4"}) == "sqlite3"
    assert display_name({"name": "sqlite"}) == "sqlite"


def test_patched_versions_are_not_a_recommendation():
    # Trivy's value is vulnerability-wide, from whichever package created
    # the record; it is never the text.
    with pytest.raises(TypeError):
        derive_recommendation(NPM, [], "1.4.2, 2.0.5")
    assert derive_recommendation(NPM, []) is None
    openssl = {"name": "openssl", "group": "debian", "version": "3.0.11-1~deb12u1",
               "purl": "pkg:deb/debian/openssl@3.0.11-1~deb12u1?distro=debian-12"}
    assert derive_recommendation(
        openssl, [_range("pkg:deb/debian/openssl", versionStartIncluding="0")]
    ) is None
    derived = derive_recommendation(NPM, [_range(versionEndExcluding="1.5")])
    assert derived.text == "Upgrade lib-a 1.4.0 to 1.5 or later."


def test_slimming_keeps_the_ranges_and_the_mirrors_only():
    slim = slim_affected_components([
        {
            "identityType": "PURL", "identity": "pkg:npm/lib-a", "versionType": "RANGE",
            "versionEndExcluding": "1.2.3", "versionStartIncluding": None,
            "uuid": "u-1",
            "affectedVersionAttributions": [
                {"source": "GITHUB", "firstSeen": 1, "uuid": "a"},
                {"source": "OSV"}, {"source": "GITHUB"},
            ],
        },
        {"identityType": "PURL"},  # no identity
        "not an entry",
    ])
    assert slim == [{
        "identityType": "PURL", "identity": "pkg:npm/lib-a", "versionType": "RANGE",
        "versionEndExcluding": "1.2.3", "sources": ["GITHUB", "OSV"],
    }]
    assert slim_affected_components(None) == []
