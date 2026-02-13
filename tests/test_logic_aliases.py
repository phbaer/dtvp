import unittest
from logic import group_vulnerabilities


class TestLogicAliases(unittest.TestCase):
    def test_group_vulnerabilities_with_aliases(self):
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

        self.assertEqual(len(groups), 1)

        g = groups[0]
        # Priority check: CVE should be preferred over GHSA
        self.assertEqual(g["id"], "CVE-2023-1234")
        self.assertIn("GHSA-XXXX-XXXX", g["aliases"])
        self.assertEqual(len(g["affected_versions"]), 1)  # same version
        self.assertEqual(
            len(g["affected_versions"][0]["components"]), 2
        )  # both component instances


if __name__ == "__main__":
    unittest.main()
