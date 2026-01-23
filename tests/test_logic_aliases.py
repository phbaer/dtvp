from logic import group_vulnerabilities


def test_group_vulnerabilities_with_aliases():
    # Finding 1: CVE-2023-1234
    # Aliases: GHSA-xxxx-xxxx
    f1 = {
        "vulnerability": {
            "vulnId": "CVE-2023-1234",
            "source": "NVD",
            "aliases": [{"cveId": "CVE-2023-1234", "ghsaId": "GHSA-xxxx-xxxx"}],
            "title": "Vuln 1 (CVE)",
            "severity": "HIGH",
        },
        "component": {"name": "libA", "version": "1.0", "uuid": "c1"},
        "analysis": {"state": "NOT_SET"},
    }

    # Finding 2: GHSA-xxxx-xxxx
    # Aliases: CVE-2023-1234
    f2 = {
        "vulnerability": {
            "vulnId": "GHSA-xxxx-xxxx",
            "source": "GITHUB",
            "aliases": [{"cveId": "CVE-2023-1234", "ghsaId": "GHSA-xxxx-xxxx"}],
            "title": "Vuln 1 (GHSA)",
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

    # New behavior: Should produce 1 group because logic.py aliases them
    groups = group_vulnerabilities(data)

    assert len(groups) == 1

    g = groups[0]
    # Priority check: CVE should be preferred over GHSA
    assert g["id"] == "CVE-2023-1234"
    assert "GHSA-xxxx-xxxx" in g["aliases"]
    assert len(g["affected_versions"]) == 1  # same version
    assert len(g["affected_versions"][0]["components"]) == 2  # both component instances
