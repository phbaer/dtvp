import pytest
from logic import calculate_statistics

def test_calculate_statistics_incomplete():
    # Scenario: All non-missing are same, but some are missing
    grouped_vulns = [
        {
            "id": "CVE-1",
            "severity": "HIGH",
            "affected_versions": [
                {
                    "project_uuid": "p1",
                    "components": [
                        {"analysis_state": "EXPLOITABLE"}
                    ]
                },
                {
                    "project_uuid": "p1", # Same project or different, doesn't matter for state aggregation here
                    "components": [
                        {"analysis_state": "NOT_SET"}
                    ]
                }
            ]
        }
    ]
    
    stats = calculate_statistics(grouped_vulns)
    assert stats["state_counts"]["INCOMPLETE"] == 1
    assert stats["finding_state_counts"]["EXPLOITABLE"] == 1
    assert stats["finding_state_counts"]["NOT_SET"] == 1
    assert stats["severity_counts"]["HIGH"] == 2
    assert stats["unique_severity_counts"]["HIGH"] == 1
    assert stats["total_findings"] == 2

def test_calculate_statistics_inconsistent():
    # Scenario: Different non-missing states
    grouped_vulns = [
        {
            "id": "CVE-2",
            "severity": "CRITICAL",
            "affected_versions": [
                {
                    "project_uuid": "p1",
                    "components": [
                        {"analysis_state": "EXPLOITABLE"}
                    ]
                },
                {
                    "project_uuid": "p2",
                    "components": [
                        {"analysis_state": "NOT_AFFECTED"}
                    ]
                }
            ]
        }
    ]
    
    stats = calculate_statistics(grouped_vulns)
    assert stats["state_counts"]["INCONSISTENT"] == 1
    assert stats["severity_counts"]["CRITICAL"] == 2
    assert stats["unique_severity_counts"]["CRITICAL"] == 1
    assert stats["total_findings"] == 2

def test_calculate_statistics_consistent():
    # Scenario: All same, none missing
    grouped_vulns = [
        {
            "id": "CVE-3",
            "severity": "MEDIUM",
            "affected_versions": [
                {
                    "project_uuid": "p1",
                    "components": [
                        {"analysis_state": "FALSE_POSITIVE"}
                    ]
                }
            ]
        }
    ]
    
    stats = calculate_statistics(grouped_vulns)
    assert stats["state_counts"]["FALSE_POSITIVE"] == 1
    assert stats["severity_counts"]["MEDIUM"] == 1
    assert stats["unique_severity_counts"]["MEDIUM"] == 1

def test_calculate_statistics_none_assessed():
    # Scenario: All NOT_SET
    grouped_vulns = [
        {
            "id": "CVE-4",
            "severity": "LOW",
            "affected_versions": [
                {
                    "project_uuid": "p1",
                    "components": [
                        {"analysis_state": "NOT_SET"}
                    ]
                },
                {
                    "project_uuid": "p2",
                    "components": [
                        {"analysis_state": "NOT_SET"}
                    ]
                }
            ]
        }
    ]
    
    stats = calculate_statistics(grouped_vulns)
    assert stats["state_counts"]["NOT_SET"] == 1
    assert stats["finding_state_counts"]["NOT_SET"] == 2
    assert stats["severity_counts"]["LOW"] == 2
    assert stats["unique_severity_counts"]["LOW"] == 1
