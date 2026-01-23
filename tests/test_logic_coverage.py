from logic import group_vulnerabilities


def test_group_vulnerabilities_sorting_fallback():
    # Scenario: Two aliased vulns, neither is CVE or GHSA.
    # Should fall back to lexicographical sorting (priority 2).

    # "BDSA-2023-0001" and "Z-CUSTOM-1"
    # Both rely on 'return (2, x)' in sort_key
    # 'BDSA...' comes before 'Z...' lexicographically.

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
    # Should pick BDSA-2023-0001 because "B" < "Z" and both have priority 2
    assert groups[0]["id"] == "BDSA-2023-0001"
