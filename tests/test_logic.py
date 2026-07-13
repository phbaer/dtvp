import dtvp.logic as logic
from fastapi.testclient import TestClient
from test_setup import mock_dt
from unittest.mock import patch
from dtvp.logic import group_vulnerabilities, BOMAnalysisCache, sanitize_rescored_vector
from dtvp.grouped_vuln_services import summarize_grouped_vulnerabilities


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


def test_group_vulnerabilities_preserves_finding_attribution():
    input_data = [
        {
            "version": {"name": "TestProj", "version": "1.0", "uuid": "uuid1"},
            "vulnerabilities": [
                {
                    "vulnerability": {
                        "vulnId": "CVE-2026-001",
                        "uuid": "vulnuuid1",
                        "severity": "HIGH",
                    },
                    "component": {"name": "libA", "version": "1.0", "uuid": "comp1"},
                    "analysis": {"state": "NOT_SET"},
                    "attribution": {"attributedOn": 1760000000000},
                }
            ],
        }
    ]

    grouped = group_vulnerabilities(input_data)

    component = grouped[0]["affected_versions"][0]["components"][0]
    assert component["attributed_on"] == 1760000000000


def test_sanitize_rescored_vector_preserves_valid():
    """Valid rescored vector (base preserved + modifiers) passes through unchanged."""
    orig = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    rescored = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MPR:L"
    assert sanitize_rescored_vector(orig, rescored) == rescored


def test_sanitize_rescored_vector_corrects_changed_base():
    """Rescored vector with altered base metrics is corrected to preserve base + extract modifiers."""
    orig = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    bad = "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H/MPR:H"
    result = sanitize_rescored_vector(orig, bad)
    assert result == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MPR:H"


def test_sanitize_rescored_vector_correction_is_not_warning(caplog):
    """Corrected vectors are normal data cleanup and should not pollute default logs."""
    orig = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    bad = "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H/MPR:H"

    with caplog.at_level("WARNING", logger="dtvp.logic"):
        assert (
            sanitize_rescored_vector(orig, bad)
            == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MPR:H"
        )

    assert "Corrected rescored vector" not in caplog.text


def test_sanitize_rescored_vector_no_modifiers_returns_none():
    """When corrected vector has no modifiers (equals original), returns None."""
    orig = "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N"
    bad = "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:N/I:N/A:N"
    assert sanitize_rescored_vector(orig, bad) is None


def test_sanitize_rescored_vector_none_inputs():
    """None/empty inputs are handled gracefully."""
    assert sanitize_rescored_vector(None, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert sanitize_rescored_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", None) is None
    assert sanitize_rescored_vector(None, None) is None


def test_sanitize_rescored_vector_cvss2():
    """CVSSv2 vectors (no CVSS: prefix) are handled correctly."""
    orig = "AV:N/AC:L/Au:N/C:P/I:P/A:P"
    rescored = "AV:N/AC:L/Au:N/C:P/I:P/A:P"
    assert sanitize_rescored_vector(orig, rescored) == rescored


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
                    "analysisDetails": "[Rescored: 5.5]\n[Rescored Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MAC:H/MA:L]\nSome details",
                },
            }
        ],
    }

    grouped = group_vulnerabilities([v1_data])
    assert len(grouped) == 1
    g = grouped[0]
    assert g["rescored_cvss"] == 5.5
    assert g["rescored_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MAC:H/MA:L"
    assert g["cvss_score"] == 9.8
    assert g["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def test_group_vulnerabilities_rescored_vector_adjusted_flag():
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
                    "analysisDetails": "[Rescored: 5.5]\n[Rescored Vector: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H]\nSome details",
                },
            }
        ],
    }

    grouped = group_vulnerabilities([v1_data])
    assert len(grouped) == 1
    g = grouped[0]
    assert g["rescored_vector_adjusted"] is True
    assert g["rescored_vector"] is None


def test_group_vulnerabilities_rescored_equal_to_base():
    v1_data = {
        "version": {"name": "TestProj", "version": "1.0", "uuid": "uuid1"},
        "vulnerabilities": [
            {
                "vulnerability": {
                    "vulnId": "CVE-EQUAL",
                    "uuid": "vuuid1",
                    "severity": "HIGH",
                    "cvssV3BaseScore": 9.8,
                },
                "component": {"name": "libA", "version": "1.0", "uuid": "comp1"},
                "analysis": {
                    "state": "NOT_SET",
                    "analysisDetails": "[Rescored: 9.8]\nSome details",
                },
            }
        ],
    }

    grouped = group_vulnerabilities([v1_data])
    assert len(grouped) == 1
    g = grouped[0]
    assert g["rescored_cvss"] == 9.8


def test_group_vulnerabilities_marks_missing_rescoring_vector_recoverable():
    historical_vector = (
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:H/RL:O/RC:C/AR:L/MAC:H/MA:N"
    )
    v1_data = {
        "version": {"name": "TestProj", "version": "1.0", "uuid": "uuid1"},
        "vulnerabilities": [
            {
                "vulnerability": {
                    "vulnId": "CVE-RESTORE",
                    "uuid": "vuuid1",
                    "severity": "HIGH",
                    "cvssV3BaseScore": 7.5,
                    "cvssV3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                "component": {"name": "sqlite", "version": "3.0", "uuid": "comp1"},
                "analysis": {
                    "analysisState": "NOT_AFFECTED",
                    "analysisDetails": (
                        "--- [Team: General] [State: NOT_AFFECTED] "
                        "[Assessed By: 100045117] "
                        "[Justification: CODE_NOT_REACHABLE] ---\n\n"
                        "sqlite not used in the product"
                    ),
                    "analysisComments": [
                        {
                            "timestamp": 1710000000000,
                            "commenter": "100045117",
                            "comment": (
                                "Details: [Rescored: 0] "
                                f"[Rescored Vector: {historical_vector}]"
                            ),
                        }
                    ],
                },
            }
        ],
    }

    grouped = group_vulnerabilities([v1_data])

    group = grouped[0]
    component = group["affected_versions"][0]["components"][0]
    candidate = component["assessment_restore"]
    assert group["assessment_restore_count"] == 1
    assert group["assessment_restore_recoverable_count"] == 1
    assert candidate["status"] == "recoverable"
    assert candidate["restored_score"] == 0
    assert candidate["restored_vector"] == historical_vector

    summary = summarize_grouped_vulnerabilities(grouped, {})[0]
    assert summary["list_metadata"]["lifecycle"] == "INCONSISTENT"
    assert summary["list_metadata"]["inconsistency_reasons"] == [
        "MISSING_RESCORING_VECTOR"
    ]
    assert summary["list_metadata"]["assessment_restore_recoverable_count"] == 1


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


def test_group_vulnerabilities_sorting_fallback():
    # Scenario: Two aliased vulns, neither is CVE or GHSA.
    # Should fall back to lexicographical sorting (priority 2).
    f1 = {
        "vulnerability": {
            "vulnId": "BDSA-2023-0001",
            "source": "BDSA",
            "aliases": [{"bdsaId": "BDSA-2023-0001", "other": "Z-CUSTOM-1"}],
            "title": "Vuln BDSA",
            "severity": "HIGH",
        },
        "component": {"name": "libA", "version": "1.0", "uuid": "c1"},
        "analysis": {"state": "NOT_SET"},
    }

    f2 = {
        "vulnerability": {
            "vulnId": "Z-CUSTOM-1",
            "source": "INTERNAL",
            "aliases": [{"bdsaId": "BDSA-2023-0001", "other": "Z-CUSTOM-1"}],
            "title": "Vuln Custom",
            "severity": "HIGH",
        },
        "component": {"name": "libA", "version": "1.0", "uuid": "c1"},
        "analysis": {"state": "NOT_SET"},
    }

    data = [
        {
            "version": {"name": "Proj", "version": "1.0", "uuid": "p1"},
            "vulnerabilities": [f1, f2],
        }
    ]

    groups = group_vulnerabilities(data)

    assert len(groups) == 1
    assert groups[0]["id"] == "BDSA-2023-0001"


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
        # Only the first team-tagged component should contribute tags to the vulnerability card.
        assert g["tags"] == ["TeamB"]
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


def test_get_auto_analysis_guidance_path_default():
    import os

    original_env = os.environ.get("DTVP_AUTO_ANALYSIS_GUIDANCE_PATH")
    if "DTVP_AUTO_ANALYSIS_GUIDANCE_PATH" in os.environ:
        del os.environ["DTVP_AUTO_ANALYSIS_GUIDANCE_PATH"]

    try:
        assert (
            logic.get_auto_analysis_guidance_path()
            == "data/auto_analysis_guidance.json"
        )
    finally:
        if original_env:
            os.environ["DTVP_AUTO_ANALYSIS_GUIDANCE_PATH"] = original_env


def test_get_auto_analysis_guidance_path_env():
    import os

    original_env = os.environ.get("DTVP_AUTO_ANALYSIS_GUIDANCE_PATH")
    os.environ["DTVP_AUTO_ANALYSIS_GUIDANCE_PATH"] = "/tmp/auto-guidance.json"

    try:
        assert logic.get_auto_analysis_guidance_path() == "/tmp/auto-guidance.json"
    finally:
        if original_env:
            os.environ["DTVP_AUTO_ANALYSIS_GUIDANCE_PATH"] = original_env
        else:
            del os.environ["DTVP_AUTO_ANALYSIS_GUIDANCE_PATH"]


def test_load_team_mapping_file_not_found():
    mapping = logic.load_team_mapping("/non/existent/path.json")
    assert mapping == {}


def test_load_team_mapping_invalid_json(tmp_path):
    p = tmp_path / "invalid.json"
    p.write_text("invalid json")

    mapping = logic.load_team_mapping(str(p))
    assert mapping == {}


def test_load_auto_analysis_guidance(tmp_path):
    p = tmp_path / "auto_analysis_guidance.json"
    p.write_text('{"components": {"keycloak-extension": "Prefer runtime evidence."}}')

    guidance = logic.load_auto_analysis_guidance(str(p))

    assert guidance == {"components": {"keycloak-extension": "Prefer runtime evidence."}}


def test_load_auto_analysis_guidance_reads_modified_file(tmp_path):
    p = tmp_path / "auto_analysis_guidance.json"
    p.write_text('{"components": {"keycloak-extension": "Prefer runtime evidence."}}')

    assert logic.load_auto_analysis_guidance(str(p)) == {
        "components": {"keycloak-extension": "Prefer runtime evidence."}
    }

    p.write_text('{"components": {"keycloak-extension": "Also check upstream Keycloak."}}')

    assert logic.load_auto_analysis_guidance(str(p)) == {
        "components": {"keycloak-extension": "Also check upstream Keycloak."}
    }


def test_load_auto_analysis_guidance_invalid_json(tmp_path):
    p = tmp_path / "invalid-auto-guidance.json"
    p.write_text("invalid json")

    guidance = logic.load_auto_analysis_guidance(str(p))

    assert guidance == {}


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
    # We are looking at lib-utils. It should inherit TeamCore only because it is the first mapped ancestor.

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
    assert tags == ["TeamCore"]


def test_tagging_vulnerable_component_uses_first_mapped_ancestor_only():
    # Hierarchy: TeamBComp (TeamB) -> TeamAComp (TeamA) -> VulnComp
    # VulnComp should inherit only TeamA because it is the first mapped ancestor.

    comp_name = "VulnComp"
    comp_uuid = "uuid-vuln"

    bom = {
        "components": [
            {"bom-ref": "b", "uuid": "uuid-b", "name": "TeamBComp"},
            {"bom-ref": "a", "uuid": "uuid-a", "name": "TeamAComp"},
            {"bom-ref": "vuln", "uuid": "uuid-vuln", "name": "VulnComp"},
        ],
        "dependencies": [
            {"ref": "b", "dependsOn": ["a"]},
            {"ref": "a", "dependsOn": ["vuln"]},
        ],
    }

    mapping = {"TeamBComp": "TeamB", "TeamAComp": "TeamA"}

    cache = BOMAnalysisCache(bom, mapping)
    tags = cache.get_tags_only(comp_uuid, comp_name)
    assert tags == ["TeamA"]


def test_tagging_mock_service_chain_prioritizes_team_a():
    client = TestClient(mock_dt.app)
    response = client.get(f"/api/v1/bom/cyclonedx/project/{mock_dt.PROJECT_V2_UUID}")
    assert response.status_code == 200

    bom = response.json()
    cache = BOMAnalysisCache(bom, {"team-a-comp": "TeamA", "team-b-comp": "TeamB"})
    tags = cache.get_tags_only(mock_dt.COMPONENT_UUID, "log4j-core")
    assert tags == ["TeamA"]


def test_tagging_multiple_ancestor_paths_collects_each_first_mapping():
    client = TestClient(mock_dt.app)
    response = client.get(f"/api/v1/bom/cyclonedx/project/{mock_dt.PROJECT_UUID}")
    assert response.status_code == 200

    bom = response.json()
    mapping = {k: v for k, v in logic.load_team_mapping().items() if k != "log4j-core"}
    cache = BOMAnalysisCache(bom, mapping)
    tags = sorted(cache.get_tags_only(mock_dt.COMPONENT_UUID, "log4j-core"))
    assert tags == ["InventoryTeam", "PaymentTeam"]


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
    assert tags == ["TeamC"]


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


def test_is_direct_dependency_classification():
    """Direct means 'immediate child of root or of a team-mapped component'."""
    bom = {
        "metadata": {"component": {"bom-ref": "root", "name": "RootProject"}},
        "components": [
            {"bom-ref": "team-comp", "uuid": "u-team", "name": "TeamLib"},
            {"bom-ref": "direct", "uuid": "u-direct", "name": "DirectLib"},
            {"bom-ref": "transitive", "uuid": "u-trans", "name": "TransitiveLib"},
        ],
        "dependencies": [
            {"ref": "root", "dependsOn": ["team-comp"]},
            {"ref": "team-comp", "dependsOn": ["direct"]},
            {"ref": "direct", "dependsOn": ["transitive"]},
        ],
    }

    mapping = {"TeamLib": "TeamA"}
    cache = BOMAnalysisCache(bom, mapping)

    # TeamLib's parent is root (no parents) → True (direct child of root)
    assert cache.is_direct_dependency("u-team", "TeamLib") is True
    # DirectLib's parent is TeamLib (team-mapped) → True
    assert cache.is_direct_dependency("u-direct", "DirectLib") is True
    # TransitiveLib's parent is DirectLib (not root, not team-mapped) → False
    assert cache.is_direct_dependency("u-trans", "TransitiveLib") is False
    assert cache.is_direct_dependency("missing", "Missing") is None


def test_group_vulnerabilities_cache_hit():

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


def test_component_analysis_results_are_cached_per_component():
    bom = {
        "components": [
            {"bom-ref": "parent", "uuid": "u1", "name": "Parent"},
            {"bom-ref": "child", "uuid": "u2", "name": "Child"},
        ],
        "dependencies": [{"ref": "parent", "dependsOn": ["child"]}],
    }

    cache = BOMAnalysisCache(bom, {"Parent": "TeamP"})

    with patch.object(
        cache,
        "_get_tags_for_ref",
        wraps=cache._get_tags_for_ref,
    ) as wrapped_tags, patch.object(
        cache,
        "_get_dependency_paths_for_ref",
        wraps=cache._get_dependency_paths_for_ref,
    ) as wrapped_paths:
        assert cache.get_tags_only("u2", "Child") == ["TeamP"]
        first_tag_calls = wrapped_tags.call_count
        assert cache.get_tags_only("u2", "Child") == ["TeamP"]
        assert wrapped_tags.call_count == first_tag_calls

        assert cache.get_dependency_paths("u2", "Child") == ["Child -> Parent"]
        first_path_calls = wrapped_paths.call_count
        assert cache.get_dependency_paths("u2", "Child") == ["Child -> Parent"]
        assert wrapped_paths.call_count == first_path_calls


def test_get_dependency_paths_truncates_when_too_many():
    bom = {
        "metadata": {"component": {"bom-ref": "root", "name": "RootProject"}},
        "components": [
            {"bom-ref": "root", "uuid": "root", "name": "RootProject"},
            {"bom-ref": "a", "uuid": "uA", "name": "A"},
            {"bom-ref": "b", "uuid": "uB", "name": "B"},
            {"bom-ref": "vuln", "uuid": "uV", "name": "VulnComp"},
        ],
        "dependencies": [
            {"ref": "root", "dependsOn": ["a", "b"]},
            {"ref": "a", "dependsOn": ["vuln"]},
            {"ref": "b", "dependsOn": ["vuln"]},
            {"ref": "vuln", "dependsOn": []},
        ],
    }

    cache = logic.BOMAnalysisCache(bom, {})
    paths, truncated = cache.get_dependency_paths("uV", "VulnComp", max_paths=1, return_truncated=True)

    assert truncated is True
    assert len(paths) == 1
    assert paths[0].startswith("VulnComp ->")


def test_group_vulnerabilities_emits_dependency_chains():
    v1_data = {
        "version": {"name": "TestProj", "version": "1.0", "uuid": "uuid1"},
        "vulnerabilities": [
            {
                "vulnerability": {"vulnId": "CVE-1", "uuid": "v1"},
                "component": {"name": "libA", "version": "1.0", "uuid": "comp1"},
                "analysis": {"state": "NOT_SET"},
            }
        ],
    }

    project_boms = {
        "uuid1": {
            "metadata": {"component": {"bom-ref": "root", "name": "TestProj"}},
            "components": [
                {"bom-ref": "root", "uuid": "root", "name": "TestProj"},
                {"bom-ref": "libA", "uuid": "comp1", "name": "libA"},
            ],
            "dependencies": [
                {"ref": "root", "dependsOn": ["libA"]},
                {"ref": "libA", "dependsOn": []},
            ],
        }
    }

    grouped = logic.group_vulnerabilities([v1_data], project_boms=project_boms)
    component = grouped[0]["affected_versions"][0]["components"][0]

    assert component["dependency_chains"] == ["libA -> TestProj"]


def test_group_vulnerabilities_can_skip_dependency_chains_for_list_builds():
    v1_data = {
        "version": {"name": "TestProj", "version": "1.0", "uuid": "uuid1"},
        "vulnerabilities": [
            {
                "vulnerability": {"vulnId": "CVE-1", "uuid": "v1"},
                "component": {"name": "libA", "version": "1.0", "uuid": "comp1"},
                "analysis": {"state": "NOT_SET"},
            }
        ],
    }

    project_boms = {
        "uuid1": {
            "metadata": {"component": {"bom-ref": "root", "name": "TestProj"}},
            "components": [
                {"bom-ref": "root", "uuid": "root", "name": "TestProj"},
                {"bom-ref": "libA", "uuid": "comp1", "name": "libA"},
            ],
            "dependencies": [
                {"ref": "root", "dependsOn": ["libA"]},
                {"ref": "libA", "dependsOn": []},
            ],
        }
    }

    grouped = logic.group_vulnerabilities(
        [v1_data],
        project_boms=project_boms,
        include_dependency_paths=False,
    )
    component = grouped[0]["affected_versions"][0]["components"][0]

    assert "dependency_chains" not in component
    assert component["is_direct_dependency"] is True


# --- Group-aware team mapping tests ---


def test_tagging_group_name_key_matches_component_with_group():
    """A 'group:name' mapping key matches a component that has that group."""
    bom = {
        "components": [
            {"bom-ref": "ref1", "uuid": "u1", "name": "core", "group": "@angular"},
        ],
        "dependencies": [],
    }
    mapping = {"@angular:core": "FrontendTeam"}

    cache = BOMAnalysisCache(bom, mapping)
    tags = cache.get_tags_only("u1", "core")
    assert tags == ["FrontendTeam"]


def test_tagging_name_only_key_matches_component_without_group():
    """A plain name key matches a component that has NO group."""
    bom = {
        "components": [
            {"bom-ref": "ref1", "uuid": "u1", "name": "core"},
        ],
        "dependencies": [],
    }
    mapping = {"core": "CoreTeam"}

    cache = BOMAnalysisCache(bom, mapping)
    tags = cache.get_tags_only("u1", "core")
    assert tags == ["CoreTeam"]


def test_tagging_name_key_matches_case_insensitively_with_exact_case_tiebreak():
    """Plain keys are case-insensitive, with deterministic exact-case preference."""
    bom = {
        "components": [
            {"bom-ref": "ref1", "uuid": "u1", "name": "Core"},
        ],
        "dependencies": [],
    }
    mapping = {"core": "LowerTeam", "Core": "ExactTeam"}

    cache = BOMAnalysisCache(bom, mapping)
    tags = cache.get_tags_only("u1", "Core")
    assert tags == ["ExactTeam"]


def test_tagging_case_sensitive_prefix_requires_exact_component_name():
    bom = {
        "components": [
            {"bom-ref": "lower", "uuid": "u1", "name": "core"},
            {"bom-ref": "exact", "uuid": "u2", "name": "Core"},
        ],
        "dependencies": [],
    }
    mapping = {"cs::Core": "ExactTeam"}

    cache = BOMAnalysisCache(bom, mapping)
    assert cache.get_tags_only("u1", "core") == []
    assert cache.get_tags_only("u2", "Core") == ["ExactTeam"]


def test_tagging_nogroup_key_requires_known_empty_group():
    bom = {
        "components": [
            {"bom-ref": "plain", "uuid": "u1", "name": "core"},
            {"bom-ref": "grouped", "uuid": "u2", "name": "core", "group": "@angular"},
        ],
        "dependencies": [],
    }
    mapping = {"nogroup::core": "NoGroupTeam", "@angular:core": "AngularTeam"}

    cache = BOMAnalysisCache(bom, mapping)
    assert cache.get_tags_only("u1", "core") == ["NoGroupTeam"]
    assert cache.get_tags_only("u2", "core") == ["AngularTeam"]


def test_tagging_nogroup_key_does_not_match_unknown_group_context():
    cache = BOMAnalysisCache({}, {"nogroup::core": "NoGroupTeam", "*": "Fallback"})

    assert cache.get_tags_only("", "core") == ["Fallback"]


def test_tagging_cs_and_nogroup_can_be_component_groups():
    bom = {
        "components": [
            {"bom-ref": "cs-ref", "uuid": "u1", "name": "core", "group": "cs"},
            {
                "bom-ref": "nogroup-ref",
                "uuid": "u2",
                "name": "core",
                "group": "nogroup",
            },
        ],
        "dependencies": [],
    }
    mapping = {"cs:core": "CaseGroupTeam", "nogroup:core": "NoGroupNameTeam"}

    cache = BOMAnalysisCache(bom, mapping)
    assert cache.get_tags_only("u1", "core") == ["CaseGroupTeam"]
    assert cache.get_tags_only("u2", "core") == ["NoGroupNameTeam"]


def test_tagging_purl_key_matches_versioned_component_and_wins_over_group():
    bom = {
        "components": [
            {
                "bom-ref": "ref1",
                "uuid": "u1",
                "name": "core",
                "group": "@angular",
                "purl": "pkg:maven/org.example/core@1.2.3",
            },
        ],
        "dependencies": [],
    }
    mapping = {
        "@angular:core": "GroupTeam",
        "purl::pkg:maven/org.example/core": "PurlTeam",
    }

    cache = BOMAnalysisCache(bom, mapping)
    assert cache.get_tags_only("u1", "core") == ["PurlTeam"]


def test_tagging_purl_key_can_match_exact_version():
    bom = {
        "components": [
            {
                "bom-ref": "ref1",
                "uuid": "u1",
                "name": "core",
                "purl": "pkg:maven/org.example/core@1.2.3",
            },
        ],
        "dependencies": [],
    }
    mapping = {
        "purl::pkg:maven/org.example/core@9.9.9": "WrongVersionTeam",
        "purl::pkg:maven/org.example/core@1.2.3": "ExactVersionTeam",
    }

    cache = BOMAnalysisCache(bom, mapping)
    assert cache.get_tags_only("u1", "core") == ["ExactVersionTeam"]


def test_tagging_case_sensitive_purl_key_requires_exact_case():
    bom = {
        "components": [
            {
                "bom-ref": "ref1",
                "uuid": "u1",
                "name": "Core",
                "purl": "pkg:maven/org.example/Core@1.2.3",
            },
        ],
        "dependencies": [],
    }
    mapping = {"cs,purl::pkg:maven/org.example/core": "LowercaseTeam"}

    cache = BOMAnalysisCache(bom, mapping)
    assert cache.get_tags_only("u1", "Core") == []


def test_group_vulnerabilities_emits_component_purl_for_auto_targeting():
    v1_data = {
        "version": {"name": "TestProj", "version": "1.0", "uuid": "proj1"},
        "vulnerabilities": [
            {
                "component": {
                    "uuid": "u1",
                    "name": "core",
                    "version": "1.2.3",
                    "purl": "pkg:maven/org.example/core@1.2.3",
                },
                "vulnerability": {
                    "uuid": "v1",
                    "vulnId": "CVE-2026-9999",
                    "severity": "HIGH",
                },
                "analysis": {"state": "NOT_SET"},
            }
        ],
    }

    grouped = group_vulnerabilities([v1_data])

    component = grouped[0]["affected_versions"][0]["components"][0]
    assert component["component_purl"] == "pkg:maven/org.example/core@1.2.3"


def test_tagging_name_only_key_does_not_match_component_with_group():
    """A plain name key must NOT match a component that HAS a group."""
    bom = {
        "components": [
            {"bom-ref": "ref1", "uuid": "u1", "name": "core", "group": "@angular"},
        ],
        "dependencies": [],
    }
    mapping = {"core": "CoreTeam"}

    cache = BOMAnalysisCache(bom, mapping)
    tags = cache.get_tags_only("u1", "core")
    # @angular/core should not get CoreTeam, it should fall to wildcard or empty
    assert tags == []


def test_tagging_group_disambiguates_same_name_components():
    """Two components named 'core' with different groups get different teams."""
    bom = {
        "components": [
            {"bom-ref": "cpp-core", "uuid": "u1", "name": "core"},
            {"bom-ref": "ng-core", "uuid": "u2", "name": "core", "group": "@angular"},
        ],
        "dependencies": [],
    }
    mapping = {"core": "NativeTeam", "@angular:core": "FrontendTeam"}

    cache = BOMAnalysisCache(bom, mapping)

    # C++ core (no group) → NativeTeam
    tags = cache.get_tags_only("u1", "core")
    assert tags == ["NativeTeam"]

    # @angular/core → FrontendTeam
    tags = cache.get_tags_only("u2", "core")
    assert tags == ["FrontendTeam"]


def test_tagging_grouped_component_without_mapping_gets_wildcard():
    """A grouped component with no matching group:name key falls to wildcard."""
    bom = {
        "components": [
            {"bom-ref": "ref1", "uuid": "u1", "name": "core", "group": "@angular"},
        ],
        "dependencies": [],
    }
    mapping = {"core": "CoreTeam", "*": "Unassigned"}

    cache = BOMAnalysisCache(bom, mapping)
    tags = cache.get_tags_only("u1", "core")
    assert tags == ["Unassigned"]


def test_tagging_grouped_component_inherits_from_parent():
    """A grouped component with no direct mapping inherits tags from its parent."""
    bom = {
        "components": [
            {"bom-ref": "app", "uuid": "u-app", "name": "my-app"},
            {"bom-ref": "ng-core", "uuid": "u1", "name": "core", "group": "@angular"},
        ],
        "dependencies": [
            {"ref": "app", "dependsOn": ["ng-core"]},
        ],
    }
    mapping = {"my-app": "AppTeam"}

    cache = BOMAnalysisCache(bom, mapping)
    tags = cache.get_tags_only("u1", "core")
    assert tags == ["AppTeam"]


def test_tagging_is_direct_dependency_respects_group_mapping():
    """is_direct_dependency recognises a group:name mapped parent as team-mapped."""
    bom = {
        "components": [
            {"bom-ref": "parent", "uuid": "u-p", "name": "core", "group": "com.example"},
            {"bom-ref": "child", "uuid": "u-c", "name": "some-lib"},
        ],
        "dependencies": [
            {"ref": "parent", "dependsOn": ["child"]},
        ],
    }
    mapping = {"com.example:core": "ExampleTeam"}

    cache = BOMAnalysisCache(bom, mapping)
    result = cache.is_direct_dependency("u-c", "some-lib")
    assert result is True


def test_tagging_group_name_with_multiple_teams():
    """A group:name key with a list value assigns multiple teams."""
    bom = {
        "components": [
            {"bom-ref": "ref1", "uuid": "u1", "name": "shared", "group": "org.internal"},
        ],
        "dependencies": [],
    }
    mapping = {"org.internal:shared": ["TeamA", "TeamB"]}

    cache = BOMAnalysisCache(bom, mapping)
    tags = cache.get_tags_only("u1", "shared")
    assert sorted(tags) == ["TeamA", "TeamB"]


def test_tagging_metadata_component_group():
    """The metadata (root) component's group is also extracted."""
    bom = {
        "metadata": {
            "component": {
                "bom-ref": "root-ref",
                "name": "core",
                "group": "com.mycompany",
            }
        },
        "components": [
            {"bom-ref": "child", "uuid": "u-c", "name": "some-lib"},
        ],
        "dependencies": [
            {"ref": "root-ref", "dependsOn": ["child"]},
        ],
    }
    mapping = {"com.mycompany:core": "RootTeam"}

    cache = BOMAnalysisCache(bom, mapping)
    tags = cache.get_tags_only("u-c", "some-lib")
    # child inherits from root which matches via group:name
    assert tags == ["RootTeam"]
