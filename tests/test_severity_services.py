import pytest

from dtvp.logic import group_vulnerabilities
from dtvp.severity_services import group_original_severity, original_severity


@pytest.mark.parametrize("score,label", [(0, "INFO"), (0.1, "LOW"), (3.9, "LOW"), (4, "MEDIUM"), (6.9, "MEDIUM"), (7, "HIGH"), (8.9, "HIGH"), (9, "CRITICAL"), (10, "CRITICAL")])
def test_original_score_boundaries(score, label):
    assert original_severity(score) == label


def test_missing_and_invalid_scores_use_source_label_not_rescored_severity():
    for score in [None, -1, 11, float("nan"), float("inf"), True, "not a score"]:
        assert original_severity(score, "high") == "HIGH"
        assert original_severity(score, "invalid") == "UNKNOWN"
    assert group_original_severity({"cvss_score": 9.8, "severity": "LOW", "rescored_cvss": 2}) == "CRITICAL"
    assert group_original_severity({"severity": "LOW", "rescored_cvss": 2}) == "UNKNOWN"


def test_group_original_severity_survives_rescoring_and_zero_score():
    groups = group_vulnerabilities([{
        "version": {"name": "Project", "uuid": "p", "version": "1"},
        "vulnerabilities": [
            {"vulnerability": {"vulnId": "CVE-1", "uuid": "v1", "cvssV3BaseScore": 9.8, "severity": "CRITICAL"},
             "component": {"uuid": "c1", "name": "lib"}, "analysis": {"analysisDetails": "[Rescored: 2.0]"}},
            {"vulnerability": {"vulnId": "CVE-2", "uuid": "v2", "cvssV4": 0, "cvssV3BaseScore": 8.0},
             "component": {"uuid": "c2", "name": "lib"}},
            {"vulnerability": {"vulnId": "CVE-3", "uuid": "v3", "severity": "HIGH"},
             "component": {"uuid": "c3", "name": "lib"}},
        ],
    }])
    by_id = {group["id"]: group for group in groups}
    assert by_id["CVE-1"]["severity"] == "LOW"
    assert by_id["CVE-1"]["original_severity"] == "CRITICAL"
    assert by_id["CVE-2"]["cvss_score"] == 0
    assert by_id["CVE-2"]["original_severity"] == "INFO"
    assert by_id["CVE-3"]["original_severity"] == "HIGH"
