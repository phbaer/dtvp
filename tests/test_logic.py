import logic
import os
from logic import group_vulnerabilities, BOMAnalysisCache


def test_group_vulnerabilities_basic():
    # Setup data
    v1_data = {
        "version": {"name": "TestProj", "version": "1.0", "uuid": "uuid1"},
        "vulnerabilities": [
            {
                "vulnerability": {
                    "vulnId": "CVE-2021-001",
                    "uuid": "vulnuuid1",
                    "title": "Vuln 1",
                    "severity": "HIGH",
                },
                "component": {"name": "libA", "version": "1.0", "uuid": "comp1"},
                "analysis": {"state": "NOT_SET"},
            }
        ],
    }

    v2_data = {
        "version": {"name": "TestProj", "version": "2.0", "uuid": "uuid2"},
        "vulnerabilities": [
            {
                "vulnerability": {
                    "vulnId": "CVE-2021-001",  # Same vuln
                    "uuid": "vulnuuid1",
                    "title": "Vuln 1",
                    "severity": "HIGH",
                },
                "component": {"name": "libA", "version": "1.0", "uuid": "comp2"},
                "analysis": {"state": "EXPLOITABLE"},
            },
            {
                "vulnerability": {
                    "vulnId": "CVE-2021-002",  # New vuln
                    "uuid": "vulnuuid2",
                    "title": "Vuln 2",
                    "severity": "LOW",
                },
                "component": {"name": "libB", "version": "1.0", "uuid": "comp3"},
                "analysis": {"state": "NOT_SET"},
            },
        ],
    }

    input_data = [v1_data, v2_data]

    # Execute
    grouped = group_vulnerabilities(input_data)

    # Verify
    assert len(grouped) == 2

    # Find CVE-2021-001 group
    g1 = next(g for g in grouped if g["id"] == "CVE-2021-001")
    assert len(g1["affected_versions"]) == 2
    assert g1["severity"] == "HIGH"

    # Check details of versions
    v1 = next(v for v in g1["affected_versions"] if v["project_version"] == "1.0")
    # Check components in v1
    assert len(v1["components"]) == 1
    assert v1["components"][0]["analysis_state"] == "NOT_SET"

    v2 = next(v for v in g1["affected_versions"] if v["project_version"] == "2.0")
    assert len(v2["components"]) == 1
    assert v2["components"][0]["analysis_state"] == "EXPLOITABLE"

    # Find CVE-2021-002 group
    g2 = next(g for g in grouped if g["id"] == "CVE-2021-002")
    assert len(g2["affected_versions"]) == 1
    assert g2["affected_versions"][0]["project_version"] == "2.0"
    assert len(g2["affected_versions"][0]["components"]) == 1


def test_group_vulnerabilities_rescored():
    v1_data = {
        "version": {"name": "TestProj", "version": "1.0", "uuid": "uuid1"},
        "vulnerabilities": [
            {
                "vulnerability": {
                    "vulnId": "CVE-1",
                    "uuid": "vuuid1",
                    "severity": "HIGH",
                    "cvssV3BaseScore": 9.8,
                    "cvssV3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                },
                "component": {"name": "libA", "version": "1.0", "uuid": "comp1"},
                "analysis": {
                    "state": "NOT_SET",
                    "analysisDetails": "[Rescored: 5.5]\n[Rescored Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:L]\nSome details",
                },
            }
        ],
    }

    grouped = group_vulnerabilities([v1_data])
    assert len(grouped) == 1
    g = grouped[0]
    assert g["rescored_cvss"] == 5.5
    assert g["rescored_vector"] == "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:L"
    assert g["cvss_score"] == 9.8
    assert g["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def test_group_vulnerabilities_missing_data():
    # Test with missing vulnerability details
    v1_data = {
        "version": {"name": "TestProj", "version": "1.0", "uuid": "uuid1"},
        "vulnerabilities": [
            {
                "vulnerability": {
                    "vulnId": "CVE-MISSING",
                    "uuid": "vuuid1",
                    # missing severity, cvss etc
                },
                "component": {"name": "libA", "version": "1.0", "uuid": "comp1"},
                "analysis": {"state": "NOT_SET"},
            }
        ],
    }

    grouped = group_vulnerabilities([v1_data])
    assert len(grouped) == 1
    g = grouped[0]
    assert g["severity"] is None
    assert g["cvss_score"] is None
    assert g["cvss_vector"] is None


def test_group_vulnerabilities_missing_id():
    # Test with entirely missing vulnId and name
    v1_data = {
        "version": {"name": "TestProj", "version": "1.0", "uuid": "uuid1"},
        "vulnerabilities": [
            {
                "vulnerability": {
                    # No vulnId or name
                    "uuid": "vuuid1",
                },
                "component": {"name": "libA", "version": "1.0", "uuid": "comp1"},
                "analysis": {"state": "NOT_SET"},
            }
        ],
    }

    grouped = group_vulnerabilities([v1_data])
    assert len(grouped) == 0


def test_group_vulnerabilities_invalid_rescored_score():
    v1_data = {
        "version": {"name": "TestProj", "version": "1.0", "uuid": "uuid1"},
        "vulnerabilities": [
            {
                "vulnerability": {
                    "vulnId": "CVE-1",
                    "uuid": "vuuid1",
                },
                "component": {"name": "libA", "version": "1.0", "uuid": "comp1"},
                "analysis": {
                    "state": "NOT_SET",
                    "analysisDetails": "[Rescored: 1.2.3]\nSome details",
                },
            }
        ],
    }

    grouped = group_vulnerabilities([v1_data])
    assert len(grouped) == 1
    g = grouped[0]
    assert g["rescored_cvss"] is None


def test_group_vulnerabilities_loose_vector():
    v1_data = {
        "version": {"name": "TestProj", "version": "1.0", "uuid": "uuid1"},
        "vulnerabilities": [
            {
                "vulnerability": {
                    "vulnId": "CVE-1",
                    "uuid": "vuuid1",
                },
                "component": {"name": "libA", "version": "1.0", "uuid": "comp1"},
                "analysis": {
                    "state": "NOT_SET",
                    "analysisDetails": "Some invalid details\nCVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L\nEnd",
                },
            },
            {
                "vulnerability": {
                    "vulnId": "CVE-2",
                    "uuid": "vuuid2",
                },
                "component": {"name": "libB", "version": "1.0", "uuid": "comp2"},
                "analysis": {
                    "state": "NOT_SET",
                    "analysisDetails": "Legacy vector: AV:N/AC:L/Au:N/C:P/I:P/A:P",
                },
            },
        ],
    }

    grouped = group_vulnerabilities([v1_data])

    g1 = next(g for g in grouped if g["id"] == "CVE-1")
    assert g1["rescored_vector"] == "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L"

    g2 = next(g for g in grouped if g["id"] == "CVE-2")
    assert g2["rescored_vector"] == "AV:N/AC:L/Au:N/C:P/I:P/A:P"


# Tagging Tests


def test_group_vulnerabilities_tagging():
    # Setup data
    v1_data = {
        "version": {"name": "TestProj", "version": "1.0", "uuid": "uuid1"},
        "vulnerabilities": [
            {
                "vulnerability": {
                    "vulnId": "CVE-TAG",
                    "uuid": "vuuid1",
                },
                "component": {"name": "libA", "version": "1.0", "uuid": "comp1"},
                "analysis": {"state": "NOT_SET"},
            }
        ],
    }

    # BOM where libA is a child of parentA
    bom = {
        "components": [
            {"bom-ref": "ref1", "uuid": "comp1", "name": "libA"},
            {"bom-ref": "ref2", "uuid": "comp2", "name": "parentA"},
        ],
        "dependencies": [
            {
                "ref": "ref2",
                "dependsOn": ["ref1"],
            },  # parentA depends on libA (actually dependsOn is typically children, wait.
            # In CycloneDX 'dependsOn' lists the dependencies OF the ref.
            # So if A depends on B, ref=A, dependsOn=[B].
            # My logic in logic.py:
            # for dep in bom["dependencies"]:
            #     parent_ref = dep.get("ref")
            #     for child_ref in dep.get("dependsOn", []):
            #         parent_map[child_ref] = parent_ref
            # This logic assumes 'ref' is the parent (dependant) and 'dependsOn' are children (dependencies).
            # If Project depends on ParentA, and ParentA depends on LibA.
            # Hierarchy: Project -> ParentA -> LibA.
            # BOM:
            # {ref: Project, dependsOn: [ParentA]}
            # {ref: ParentA, dependsOn: [LibA]}
            # My logic builds: ParentA -> Project, LibA -> ParentA.
            # Yes, parent_map[child] = parent.
            # So if I want to tag LibA with ParentA's team.
            # LibA is the child. ParentA is the parent.
            # So dependencies needs: ref="ref2" (parentA), dependsOn=["ref1" (libA)]
        ],
    }

    project_boms = {"uuid1": bom}

    # Mock load_team_mapping

    original_load = logic.load_team_mapping
    try:
        logic.load_team_mapping = lambda path=None: {
            "parentA": "TeamA",
            "libA": "TeamB",
        }

        grouped = group_vulnerabilities([v1_data], project_boms)

        assert len(grouped) == 1
        g = grouped[0]
        # Should have both TeamB (direct match) and TeamA (parent match)
        assert "TeamA" in g["tags"]
        assert "TeamB" in g["tags"]
        assert len(g["tags"]) == 2

    finally:
        logic.load_team_mapping = original_load


def test_get_team_mapping_path_default():
    import os

    original_env = os.environ.get("TEAM_MAPPING_PATH")
    if "TEAM_MAPPING_PATH" in os.environ:
        del os.environ["TEAM_MAPPING_PATH"]

    try:
        assert logic.get_team_mapping_path() == "data/team_mapping.json"
    finally:
        if original_env:
            os.environ["TEAM_MAPPING_PATH"] = original_env


def test_get_team_mapping_path_env():
    import os

    original_env = os.environ.get("TEAM_MAPPING_PATH")
    os.environ["TEAM_MAPPING_PATH"] = "/tmp/test.json"

    try:
        assert logic.get_team_mapping_path() == "/tmp/test.json"
    finally:
        if original_env:
            os.environ["TEAM_MAPPING_PATH"] = original_env
        else:
            del os.environ["TEAM_MAPPING_PATH"]


def test_load_team_mapping_file_not_found():
    mapping = logic.load_team_mapping("/non/existent/path.json")
    assert mapping == {}


def test_load_team_mapping_invalid_json(tmp_path):
    p = tmp_path / "invalid.json"
    p.write_text("invalid json")

    mapping = logic.load_team_mapping(str(p))
    assert mapping == {}


def test_load_team_mapping_valid(tmp_path):
    import json

    p = tmp_path / "valid.json"
    data = {"comp": "team"}
    p.write_text(json.dumps(data))

    mapping = logic.load_team_mapping(str(p))
    assert mapping == data


def test_tagging_no_bom():
    comp_uuid = "uuid1"
    comp_name = "libA"
    bom = {}
    mapping = {"libA": "TeamA"}

    cache = BOMAnalysisCache(bom, mapping)
    tags = cache.get_tags_only(comp_uuid, comp_name)
    assert tags == ["TeamA"]


def test_tagging_bom_ref_mismatch():
    comp_uuid = "uuid1"
    comp_name = "libA"
    bom = {"components": [{"bom-ref": "ref1", "uuid": "uuid2", "name": "libB"}]}
    mapping = {"libA": "TeamA"}

    cache = BOMAnalysisCache(bom, mapping)
    tags = cache.get_tags_only(comp_uuid, comp_name)
    assert tags == ["TeamA"]  # matched by name directly


def test_tagging_bom_hierarchy():
    # Hierarchy: custom-app (TeamX) -> lib-core (TeamCore) -> lib-utils
    # We are looking at lib-utils. It should inherit TeamCore and TeamX.

    comp_name = "lib-utils"
    comp_uuid = "uuid3"

    bom = {
        "components": [
            {"bom-ref": "app", "uuid": "uuid1", "name": "custom-app"},
            {"bom-ref": "core", "uuid": "uuid2", "name": "lib-core"},
            {"bom-ref": "utils", "uuid": "uuid3", "name": "lib-utils"},
        ],
        "dependencies": [
            {"ref": "app", "dependsOn": ["core"]},
            {"ref": "core", "dependsOn": ["utils"]},
        ],
    }

    mapping = {"custom-app": "TeamX", "lib-core": "TeamCore"}

    cache = BOMAnalysisCache(bom, mapping)
    tags = cache.get_tags_only(comp_uuid, comp_name)
    assert set(tags) == {"TeamX", "TeamCore"}


def test_tagging_catch_all():
    comp_uuid = "uuid1"
    comp_name = "unknown-lib"
    bom = {}
    mapping = {"existing-lib": "TeamA", "*": "CatchAllTeam"}

    cache = BOMAnalysisCache(bom, mapping)
    tags = cache.get_tags_only(comp_uuid, comp_name)
    assert tags == ["CatchAllTeam"]


def test_tagging_catch_all_ignored_if_match():
    comp_uuid = "uuid1"
    comp_name = "existing-lib"
    bom = {}
    mapping = {"existing-lib": "TeamA", "*": "CatchAllTeam"}

    cache = BOMAnalysisCache(bom, mapping)
    tags = cache.get_tags_only(comp_uuid, comp_name)
    assert tags == ["TeamA"]  # Should NOT include CatchAllTeam


def test_tagging_deep_hierarchy_multiple_matches():
    # Hierarchy: Top (TeamA) -> Mid (NoTeam) -> Low (TeamB) -> VulnComp (TeamC)

    comp_uuid = "v-uuid"
    comp_name = "VulnComp"

    bom = {
        "components": [
            {"bom-ref": "top", "uuid": "u1", "name": "Top"},
            {"bom-ref": "mid", "uuid": "u2", "name": "Mid"},
            {"bom-ref": "low", "uuid": "u3", "name": "Low"},
            {"bom-ref": "vuln", "uuid": "v-uuid", "name": "VulnComp"},
        ],
        "dependencies": [
            {"ref": "top", "dependsOn": ["mid"]},
            {"ref": "mid", "dependsOn": ["low"]},
            {"ref": "low", "dependsOn": ["vuln"]},
        ],
    }

    mapping = {"Top": "TeamA", "Low": "TeamB", "VulnComp": "TeamC"}

    cache = BOMAnalysisCache(bom, mapping)
    tags = cache.get_tags_only(comp_uuid, comp_name)
    assert set(tags) == {"TeamA", "TeamB", "TeamC"}


def test_build_parent_map_edge_cases():
    assert logic.build_parent_map({}) == {}
    assert logic.build_parent_map({"dependencies": []}) == {}


def test_get_component_analysis_edge_cases():
    # No ref in component (line 72)
    bom = {"components": [{"uuid": "uuid1", "name": "libA"}]}
    cache = BOMAnalysisCache(bom, {})
    paths = cache.get_dependency_paths("uuid1", "libA")
    assert paths == ["libA"]

    # Match by ref (line 82)
    bom = {
        "components": [
            {"bom-ref": "ref1", "uuid": "uuid2", "name": "libA"},
            {"bom-ref": "parent", "uuid": "uuidP", "name": "parent"},
        ],
        "dependencies": [{"ref": "parent", "dependsOn": ["ref1"]}],
    }
    # Match uuid2 by calling with comp_uuid="ref1"
    cache = BOMAnalysisCache(bom, {"parent": "TeamP"})
    tags = cache.get_tags_only("ref1", "libA")
    assert "TeamP" in tags

    # Match by name fallback (line 84)
    bom = {
        "components": [
            {"bom-ref": "ref1", "uuid": "uuid2", "name": "libA"},
            {"bom-ref": "parent", "uuid": "uuidP", "name": "parent"},
        ],
        "dependencies": [{"ref": "parent", "dependsOn": ["ref1"]}],
    }
    # Call with non-matching uuid but matching name
    cache = BOMAnalysisCache(bom, {"parent": "TeamP"})
    tags = cache.get_tags_only("uuid-other", "libA")
    assert "TeamP" in tags


def test_get_component_analysis_cycle():
    # Cycle: A -> B -> A
    bom = {
        "components": [
            {"bom-ref": "refA", "uuid": "uA", "name": "A"},
            {"bom-ref": "refB", "uuid": "uB", "name": "B"},
        ],
        "dependencies": [
            {"ref": "refA", "dependsOn": ["refB"]},
            {"ref": "refB", "dependsOn": ["refA"]},
        ],
    }
    cache = BOMAnalysisCache(bom, {})
    paths = cache.get_dependency_paths("uA", "A")
    # Should not crash. In a cycle it should handle visited refs.
    assert "A" in paths


def test_get_component_analysis_disconnected():
    # Bom exists but no parents for target
    bom = {
        "components": [{"bom-ref": "refA", "uuid": "uA", "name": "A"}],
        "dependencies": [],
    }
    cache = BOMAnalysisCache(bom, {})
    paths = cache.get_dependency_paths("uA", "A")
    assert paths == ["A"]


def test_get_component_analysis_redundant_parents():
    # BOM with child listed twice for same parent
    bom = {
        "components": [
            {"bom-ref": "parent", "uuid": "u1", "name": "Parent"},
            {"bom-ref": "child", "uuid": "u2", "name": "Child"},
        ],
        "dependencies": [
            {"ref": "parent", "dependsOn": ["child", "child"]},
        ],
    }
    cache = BOMAnalysisCache(bom, {})
    paths = cache.get_dependency_paths("u2", "Child")
    # Should only have one path and not crash from redundant processing
    assert paths == ["Child -> Parent"]


def test_group_vulnerabilities_cache_hit():
    import logic

    # Test to ensure that multiple vulnerabilities for the same component use the cache
    v1_data = {
        "version": {"name": "TestProj", "version": "1.0", "uuid": "uuid1"},
        "vulnerabilities": [
            {
                "vulnerability": {"vulnId": "CVE-1", "uuid": "v1"},
                "component": {"name": "libA", "version": "1.0", "uuid": "comp1"},
                "analysis": {"state": "NOT_SET"},
            },
            {
                "vulnerability": {"vulnId": "CVE-2", "uuid": "v2"},
                # Same component
                "component": {"name": "libA", "version": "1.0", "uuid": "comp1"},
                "analysis": {"state": "NOT_SET"},
            },
        ],
    }

    bom = {
        "components": [
            {"bom-ref": "ref1", "uuid": "comp1", "name": "libA"},
        ],
        "dependencies": [],
    }
    project_boms = {"uuid1": bom}

    grouped = logic.group_vulnerabilities([v1_data], project_boms)
    assert len(grouped) == 2
