import unittest
from logic import group_vulnerabilities


class TestAliasGrouping(unittest.TestCase):
    def test_alias_unidirectional(self):
        """
        Finding 1 (CVE) knows about GHSA alias.
        Finding 2 (GHSA) knows nothing.
        Should be grouped together.
        """
        data = [
            {
                "version": {"uuid": "p1", "name": "P1", "version": "1.0"},
                "vulnerabilities": [
                    {
                        "uuid": "f1",
                        "vulnerability": {
                            "uuid": "v1",
                            "vulnId": "CVE-2023-1000",
                            "source": "NVD",
                            "aliases": [
                                {"cveId": "CVE-2023-1000", "ghsaId": "GHSA-1000"}
                            ],
                        },
                    },
                    {
                        "uuid": "f2",
                        "vulnerability": {
                            "uuid": "v2",
                            "vulnId": "GHSA-1000",
                            "source": "GITHUB",
                            "aliases": [],  # Knows nothing
                        },
                    },
                ],
            }
        ]

        result = group_vulnerabilities(data)

        self.assertEqual(
            len(result), 1, "Should be grouped into 1 canonical vulnerability"
        )
        self.assertEqual(
            result[0]["id"], "CVE-2023-1000", "Should prefer CVE as canonical ID"
        )
        self.assertIn(
            "GHSA-1000", result[0]["aliases"], "GHSA should be listed as alias"
        )

    def test_alias_bidirectional(self):
        """
        Finding 1 (CVE) knows about GHSA.
        Finding 2 (GHSA) knows about CVE.
        Should be grouped.
        """
        data = [
            {
                "version": {"uuid": "p1", "name": "P1", "version": "1.0"},
                "vulnerabilities": [
                    {
                        "uuid": "f1",
                        "vulnerability": {
                            "vulnId": "CVE-2023-2000",
                            "aliases": [{"ghsaId": "GHSA-2000"}],
                        },
                    },
                    {
                        "uuid": "f2",
                        "vulnerability": {
                            "vulnId": "GHSA-2000",
                            "aliases": [{"cveId": "CVE-2023-2000"}],
                        },
                    },
                ],
            }
        ]

        result = group_vulnerabilities(data)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["id"], "CVE-2023-2000")

    def test_alias_transitive(self):
        """
        CVE -> GHSA
        GHSA -> NPM
        Should group CVE, GHSA, NPM.
        """
        data = [
            {
                "version": {"uuid": "p1", "name": "P1"},
                "vulnerabilities": [
                    {
                        "vulnerability": {
                            "vulnId": "CVE-2023-3000",
                            "aliases": [{"ghsaId": "GHSA-3000"}],
                        }
                    },
                    {
                        "vulnerability": {
                            "vulnId": "GHSA-3000",
                            # Knows about NPM, but maybe not CVE directly here
                            "aliases": [{"sonatypeId": "sonatype-3000"}],
                        }
                    },
                    {"vulnerability": {"vulnId": "sonatype-3000", "aliases": []}},
                ],
            }
        ]

        result = group_vulnerabilities(data)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["id"], "CVE-2023-3000")
        self.assertIn("GHSA-3000", result[0]["aliases"])
        self.assertIn("SONATYPE-3000", result[0]["aliases"])

    def test_alias_transitive_complex(self):
        """
        Scenario:
        Finding A: CVE-100 (alias: GHSA-100)
        Finding B: GHSA-100 (alias: [])
        Finding C: GHSA-100 (alias: []) - Duplicate finding in another version
        Should all be grouped under CVE-100.
        """
        data = [
            {
                "version": {"uuid": "p1", "name": "P1"},
                "vulnerabilities": [
                    {
                        "uuid": "f1",
                        "vulnerability": {
                            "vulnId": "CVE-2023-4000",
                            "aliases": [{"ghsaId": "GHSA-4000"}],
                        },
                    },
                    {
                        "uuid": "f2",
                        "vulnerability": {"vulnId": "GHSA-4000", "aliases": []},
                    },
                ],
            },
            {
                "version": {"uuid": "p2", "name": "P1-v2", "version": "2.0"},
                "vulnerabilities": [
                    {
                        "uuid": "f3",
                        "vulnerability": {
                            "vulnId": "GHSA-4000",
                            "aliases": [],  # Still knows nothing about CVE
                        },
                    }
                ],
            },
        ]

        result = group_vulnerabilities(data)
        self.assertEqual(
            len(result), 1, "Transitive alias across versions should group together"
        )
        self.assertEqual(result[0]["id"], "CVE-2023-4000")

    def test_alias_mixed_case(self):
        """
        Finding A: CVE-Mixed (alias: ghsa-mixed) - lowercase alias ref
        Finding B: GHSA-MIXED (alias: []) - uppercase ID
        Should group if logic handles normalization, otherwise fail.
        """
        data = [
            {
                "version": {"uuid": "p1", "name": "P1", "version": "1.0"},
                "vulnerabilities": [
                    {
                        "uuid": "f1",
                        "vulnerability": {
                            "vulnId": "CVE-Mixed",
                            "aliases": [{"ghsaId": "ghsa-mixed"}],
                        },
                    },
                    {
                        "uuid": "f2",
                        "vulnerability": {"vulnId": "GHSA-MIXED", "aliases": []},
                    },
                ],
            }
        ]

        result = group_vulnerabilities(data)
        # If strict case: 2 groups. If normalized: 1 group.
        # User wants them consolidated.
        self.assertEqual(len(result), 1, "Should group mixed case aliases")
        self.assertEqual(result[0]["id"], "CVE-MIXED")

    def test_alias_shared_unknown_root(self):
        """
        Finding A: GHSA-1 (alias: CVE-1)
        Finding B: GHSA-2 (alias: CVE-1)
        Note: CVE-1 itself is NOT a finding in the set.
        Should they be grouped?
        Yes, because they share a root (CVE-1).
        """
        data = [
            {
                "version": {"uuid": "p1", "name": "P1"},
                "vulnerabilities": [
                    {
                        "uuid": "f1",
                        "vulnerability": {
                            "vulnId": "GHSA-1",
                            "aliases": [{"cveId": "CVE-common"}],
                        },
                    },
                    {
                        "uuid": "f2",
                        "vulnerability": {
                            "vulnId": "GHSA-2",
                            "aliases": [{"cveId": "CVE-common"}],
                        },
                    },
                ],
            }
        ]

        result = group_vulnerabilities(data)
        self.assertEqual(
            len(result),
            1,
            "Findings sharing a common alias (even if not present) should group",
        )
        self.assertEqual(result[0]["id"], "CVE-COMMON")
        # Note: logic.py prioritizes CVE > GHSA. If CVE-common is in the DS, it should be chosen as root if possible?
        # Actually logic.py:
        # 1. ds.find(GHSA-1) -> CVE-common (if unioned properly)
        # 2. keys in ds.parent are GHSA-1, CVE-common, GHSA-2.
        # 3. sorting roots...
        # Let's see if this passes.


if __name__ == "__main__":
    unittest.main()
