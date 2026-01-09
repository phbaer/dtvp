from logic import group_vulnerabilities


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
    import logic

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
    import logic
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
    import logic
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
    import logic

    mapping = logic.load_team_mapping("/non/existent/path.json")
    assert mapping == {}


def test_load_team_mapping_invalid_json(tmp_path):
    import logic

    p = tmp_path / "invalid.json"
    p.write_text("invalid json")

    mapping = logic.load_team_mapping(str(p))
    assert mapping == {}


def test_load_team_mapping_valid(tmp_path):
    import logic
    import json

    p = tmp_path / "valid.json"
    data = {"comp": "team"}
    p.write_text(json.dumps(data))

    mapping = logic.load_team_mapping(str(p))
    assert mapping == data


def test_tagging_no_bom():
    import logic

    comp_uuid = "uuid1"
    comp_name = "libA"
    bom = {}
    mapping = {"libA": "TeamA"}

    tags = logic.get_tags_for_component(comp_uuid, comp_name, bom, mapping)
    assert tags == ["TeamA"]


def test_tagging_bom_ref_mismatch():
    import logic

    comp_uuid = "uuid1"
    comp_name = "libA"
    bom = {"components": [{"bom-ref": "ref1", "uuid": "uuid2", "name": "libB"}]}
    mapping = {"libA": "TeamA"}

    tags = logic.get_tags_for_component(comp_uuid, comp_name, bom, mapping)
    assert tags == ["TeamA"]  # matched by name directly


def test_tagging_bom_hierarchy():
    import logic

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

    tags = logic.get_tags_for_component(comp_uuid, comp_name, bom, mapping)
    assert set(tags) == {"TeamX", "TeamCore"}
