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
    v1 = next(
        v for v in g1["affected_versions"] if v["project_version"] == "1.0"
    )
    # Check components in v1
    assert len(v1["components"]) == 1
    assert v1["components"][0]["analysis_state"] == "NOT_SET"

    v2 = next(
        v for v in g1["affected_versions"] if v["project_version"] == "2.0"
    )
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
                    "analysisDetails": "[Rescored: 5.5]\n[Rescored Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:L]\nSome details"
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
                    "analysisDetails": "[Rescored: NotANumber]\nSome details"
                },
            }
        ],
    }

    grouped = group_vulnerabilities([v1_data])
    assert len(grouped) == 1
    g = grouped[0]
    assert g["rescored_cvss"] is None
