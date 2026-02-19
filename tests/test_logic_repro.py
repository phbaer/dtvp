import logic
from logic import group_vulnerabilities


def test_group_vulnerabilities_rescored_equal_to_base():
    # Test that a rescored value equal to the base score is NOT ignored
    # or confirm it IS ignored (which would be the bug)
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
    # If the bug exists, this will be None
    # We want it to be 9.8
    assert g["rescored_cvss"] == 9.8
