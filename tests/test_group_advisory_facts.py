"""The advisory facts a group carries for the assessment summary: CWEs and
the source's recommendation, from the findings Dependency-Track serves."""

from dtvp.grouped_vuln_services import summarize_grouped_vulnerabilities
from dtvp.logic import group_vulnerabilities, vulnerability_cwes


def _version(*vulnerabilities):
    return {
        "version": {"uuid": "p1", "name": "P1", "version": "1.0"},
        "vulnerabilities": [
            {"uuid": f"f{index}", "vulnerability": vulnerability}
            for index, vulnerability in enumerate(vulnerabilities)
        ],
    }


def test_cwes_come_from_the_list_or_the_older_single_fields():
    assert vulnerability_cwes(
        {"cwes": [{"cweId": 79, "name": " XSS "}, {"cweId": "79"}, {"cweId": "x"}, 20]}
    ) == [{"id": 79, "name": "XSS"}, {"id": 20, "name": None}]
    assert vulnerability_cwes({"cweId": 502, "cweName": "Deserialization"}) == [
        {"id": 502, "name": "Deserialization"}
    ]
    assert vulnerability_cwes({}) == []


def test_group_carries_cwes_and_recommendation_into_the_summary():
    groups = group_vulnerabilities([
        _version(
            {
                "uuid": "v1",
                "vulnId": "CVE-2023-1000",
                "source": "NVD",
                "aliases": [{"cveId": "CVE-2023-1000", "ghsaId": "GHSA-1000"}],
                "recommendation": "  ",
            },
            {
                "uuid": "v2",
                "vulnId": "GHSA-1000",
                "source": "GITHUB",
                "cwes": [{"cweId": 79, "name": "Cross-site Scripting"}],
                "recommendation": "Upgrade to 2.0.",
            },
        )
    ])
    assert len(groups) == 1
    # The CVE record has neither; its GitHub alias fills both in.
    assert groups[0]["cwes"] == [{"id": 79, "name": "Cross-site Scripting"}]
    assert groups[0]["recommendation"] == "Upgrade to 2.0."

    summary = summarize_grouped_vulnerabilities(groups, {})[0]
    assert summary["cwes"] == [{"id": 79, "name": "Cross-site Scripting"}]
    assert summary["recommendation"] == "Upgrade to 2.0."
