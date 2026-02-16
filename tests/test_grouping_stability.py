import unittest
from logic import group_vulnerabilities


class TestGroupingStability(unittest.TestCase):
    def setUp(self):
        # Create mock data mimicking what comes from Dependency-Track
        self.entry1 = {
            "version": {"uuid": "p1", "name": "Project A", "version": "1.0"},
            "vulnerabilities": [
                {
                    "uuid": "f1",
                    "vulnerability": {
                        "uuid": "v1",
                        "vulnId": "CVE-2023-0001",
                        "severity": "HIGH",
                        "cvssV3BaseScore": 8.0,
                    },
                    "component": {"uuid": "c1", "name": "lib-a", "version": "1.0"},
                    "analysis": {"state": "NOT_SET"},
                }
            ],
        }

        self.entry2 = {
            "version": {"uuid": "p2", "name": "Project A", "version": "2.0"},
            "vulnerabilities": [
                {
                    "uuid": "f2",
                    "vulnerability": {
                        "uuid": "v1",
                        "vulnId": "CVE-2023-0001",  # Same vuln
                        "severity": "HIGH",
                        "cvssV3BaseScore": 8.0,
                    },
                    "component": {"uuid": "c2", "name": "lib-a", "version": "1.0"},
                    "analysis": {"state": "NOT_SET"},
                },
                {
                    "uuid": "f3",
                    "vulnerability": {
                        "uuid": "v2",
                        "vulnId": "CVE-2023-0002",  # Different vuln
                        "severity": "MEDIUM",
                        "cvssV3BaseScore": 5.0,
                    },
                    "component": {"uuid": "c3", "name": "lib-b", "version": "1.0"},
                    "analysis": {"state": "NOT_SET"},
                },
            ],
        }

        self.entry3 = {
            "version": {"uuid": "p3", "name": "Project A", "version": "3.0"},
            "vulnerabilities": [
                {
                    "uuid": "f4",
                    "vulnerability": {
                        "uuid": "v2",
                        "vulnId": "CVE-2023-0002",
                        "severity": "MEDIUM",
                        "cvssV3BaseScore": 5.0,
                    },
                    "component": {"uuid": "c4", "name": "lib-b", "version": "1.0"},
                    "analysis": {"state": "NOT_SET"},
                }
            ],
        }

    def test_stability(self):
        # Initial order
        data = [self.entry1, self.entry2, self.entry3]

        # Run grouping
        result1 = group_vulnerabilities(data)

        # Extract IDs to verify consistency
        ids1 = [g["id"] for g in result1]

        # Run with shuffled data
        data_shuffled = [self.entry3, self.entry1, self.entry2]
        result2 = group_vulnerabilities(data_shuffled)
        ids2 = [g["id"] for g in result2]

        # The groups list order currently depends on insertion order or dict iteration.
        # If logic.py does NOT sort the final result, ids1 and ids2 might differ.
        self.assertEqual(
            ids1, ids2, "Output order should be deterministic regardless of input order"
        )

        # Check affected versions order inside a group
        cve1_group1 = next(g for g in result1 if g["id"] == "CVE-2023-0001")
        affected1 = [av["project_version"] for av in cve1_group1["affected_versions"]]

        cve1_group2 = next(g for g in result2 if g["id"] == "CVE-2023-0001")
        affected2 = [av["project_version"] for av in cve1_group2["affected_versions"]]

        self.assertEqual(
            affected1, affected2, "Affected versions order should be deterministic"
        )


if __name__ == "__main__":
    unittest.main()
