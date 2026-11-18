"""CycloneDX inventory and VDR built from DTVP's records."""

from datetime import UTC, datetime

from dtvp.assessment_model import parse_assessment
from dtvp.cyclonedx_export import build_inventory, build_vdr, valid_property_prefix

VECTOR = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
ASSESSED = (
    f"[Rescored: 2.5] [Rescored Vector: {VECTOR}]\n\n[Status: Pending Review]\n\n"
    "--- [Team: General] [State: NOT_AFFECTED] [Assessed By: alice] "
    "[Reviewed By: rita] [Justification: CODE_NOT_REACHABLE] ---\n"
    "The parser is never called.\n\n"
    "--- [Team: Core] [State: NOT_AFFECTED] [Assessed By: bob] "
    "[Date: 1794561289026] [Justification: CODE_NOT_REACHABLE] "
    "[Ticket: EXP-1001] ---\n"
    "Checked the call sites.\n\n"
    "--- [Team: Old] [State: EXPLOITABLE] [Historical: yes] ---\nOutdated."
)
BOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "metadata": {"component": {"name": "App", "version": "1.0"}},
    "components": [
        {"bom-ref": "c1", "name": "lib-a", "version": "1.0", "purl": "pkg:npm/lib-a@1.0"},
        {"bom-ref": "ref-b", "name": "lib-b", "version": "2.0", "purl": "pkg:npm/lib-b@2.0"},
    ],
    "vulnerabilities": [{"id": "stale"}],
}


def _finding(component, vuln="CVE-2026-1", uuid="v1", **vulnerability):
    return {
        "component": component,
        "vulnerability": {
            "uuid": uuid, "vulnId": vuln, "source": "NVD", "severity": "HIGH",
            "cvssV3BaseScore": 7.5,
            "cvssV3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            "description": "A flaw.", "cwes": [{"cweId": 79}],
            "aliases": [{"cveId": vuln, "ghsaId": "GHSA-aaaa-bbbb-cccc"}],
            **vulnerability,
        },
    }


C1 = {"uuid": "c1", "name": "lib-a", "version": "1.0"}
C2 = {"uuid": "other-uuid", "name": "lib-b", "version": "2.0", "purl": "pkg:npm/lib-b@2.0"}
NOW = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)


def _vdr(findings, texts, **options):
    return build_vdr(
        BOM, findings,
        [parse_assessment(state, text, False) for state, text in texts],
        generated_at=NOW, **options,
    )


def test_inventory_is_the_bom_without_vulnerabilities():
    inventory = build_inventory(BOM)
    assert "vulnerabilities" not in inventory
    assert inventory["components"] == BOM["components"]
    assert "vulnerabilities" in BOM  # the stored BOM is not changed


def test_an_assessment_is_written_in_standard_fields():
    document = _vdr(
        [_finding(C1)], [("NOT_AFFECTED", ASSESSED)],
        assessment_source="ACME PSIRT", property_prefix="acme", tool_version="1.2.3",
    )

    assert document["specVersion"] == "1.5"  # annotations need 1.5
    assert document["metadata"]["timestamp"] == "2026-11-18T12:00:00+00:00"
    assert {"name": "acme:export", "value": "vdr"} in document["metadata"]["properties"]
    [entry] = document["vulnerabilities"]
    assert entry["id"] == "CVE-2026-1" and entry["bom-ref"] == "v1"
    assert entry["source"] == {"name": "NVD"}
    assert entry["references"] == [
        {"id": "GHSA-aaaa-bbbb-cccc", "source": {"name": "GITHUB"}}
    ]
    assert entry["cwes"] == [79] and entry["description"] == "A flaw."
    assert entry["affects"] == [{"ref": "c1"}]
    assert entry["analysis"] == {
        "state": "not_affected",
        "justification": "code_not_reachable",
        "detail": "The parser is never called.",
    }
    advisory, own = entry["ratings"]
    assert advisory == {
        "source": {"name": "NVD"}, "score": 7.5, "severity": "high",
        "method": "CVSSv31", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    }
    assert own == {
        "source": {"name": "ACME PSIRT"}, "score": 2.5, "severity": "low",
        "method": "CVSSv31", "vector": VECTOR,
        "justification": "The parser is never called.",
    }
    assert entry["properties"] == [
        {"name": "acme:assessed_by", "value": "alice"},
        {"name": "acme:reviewed_by", "value": "rita"},
        {"name": "acme:spr", "value": "EXP-1001"},
        {"name": "acme:pending_review", "value": "true"},
        {"name": "acme:team_state", "value": "Core=NOT_AFFECTED"},
    ]
    # One annotation per current team; General is the analysis itself and
    # historical blocks are left out.
    assert document["annotations"] == [
        {
            "subjects": ["v1"],
            # One annotator, as the schema requires: the team, with the
            # assessor as its contact.
            "annotator": {
                "organization": {"name": "Core", "contact": [{"name": "bob"}]},
            },
            "timestamp": "2026-11-13T09:14:49.026000+00:00",
            "text": "Checked the call sites.",
        }
    ]
    # No markup is left anywhere in the document.
    assert "[Team:" not in str(document) and "[Rescored" not in str(document)


def test_findings_in_triage_and_without_assessment_are_listed():
    document = _vdr(
        [_finding(C1), _finding(C1, "CVE-2026-2", "v2", aliases=[])],
        [("IN_TRIAGE", ""), ("NOT_SET", "")],
    )
    triage, unset = document["vulnerabilities"]
    assert triage["analysis"] == {"state": "in_triage"}
    assert "analysis" not in unset and unset["affects"] == [{"ref": "c1"}]
    assert "annotations" not in document
    assert len(unset["ratings"]) == 1  # the advisory's rating only


def test_findings_sharing_an_assessment_are_one_entry_and_differing_ones_are_not():
    shared = _vdr(
        [_finding(C1), _finding(C2)],
        [("NOT_AFFECTED", ASSESSED), ("NOT_AFFECTED", ASSESSED)],
    )
    [entry] = shared["vulnerabilities"]
    # The second component is found in the BOM by its package URL.
    assert entry["affects"] == [{"ref": "c1"}, {"ref": "ref-b"}]
    assert len(shared["annotations"]) == 1

    split = _vdr(
        [_finding(C1), _finding(C2)],
        [("NOT_AFFECTED", ASSESSED), ("EXPLOITABLE", "Reachable here.")],
    )
    first, second = split["vulnerabilities"]
    assert (first["bom-ref"], second["bom-ref"]) == ("v1", "v1#2")
    assert second["analysis"] == {"state": "exploitable", "detail": "Reachable here."}
    assert second["affects"] == [{"ref": "ref-b"}]


def test_free_text_is_the_rationale_or_a_property():
    plain = _vdr([_finding(C1)], [("NOT_AFFECTED", "Legacy note.")])
    assert plain["vulnerabilities"][0]["analysis"]["detail"] == "Legacy note."
    assert "properties" not in plain["vulnerabilities"][0]

    both = _vdr(
        [_finding(C1)],
        [("NOT_AFFECTED", "Side note.\n\n--- [Team: General] [State: NOT_AFFECTED] ---\nReason.")],
    )
    entry = both["vulnerabilities"][0]
    assert entry["analysis"]["detail"] == "Reason."
    assert {"name": "dtvp:free_text", "value": "Side note."} in entry["properties"]


def test_property_prefix_must_be_an_identifier():
    assert valid_property_prefix("acme.sec-1")
    assert not valid_property_prefix("a:b") and not valid_property_prefix("")


def test_a_component_only_a_finding_names_is_added_to_both_documents():
    stray = {"uuid": "c9", "name": "lib-z", "version": "3.1", "purl": "pkg:npm/lib-z@3.1"}
    findings = [_finding(C1), _finding(stray, "CVE-2026-9", "v9", aliases=[])]

    inventory = build_inventory(BOM, findings, property_prefix="acme")
    vdr = build_vdr(
        BOM, findings, [parse_assessment("NOT_SET", "", False)] * 2,
        property_prefix="acme", generated_at=NOW,
    )

    added = {
        "type": "library", "bom-ref": "c9", "name": "lib-z", "version": "3.1",
        "purl": "pkg:npm/lib-z@3.1",
        "properties": [{"name": "acme:added_from_finding", "value": "true"}],
    }
    assert inventory["components"][-1] == added and len(inventory["components"]) == 3
    assert vdr["components"] == inventory["components"]
    refs = {component["bom-ref"] for component in vdr["components"]}
    assert all(
        affected["ref"] in refs
        for entry in vdr["vulnerabilities"] for affected in entry["affects"]
    )
    assert len(BOM["components"]) == 2  # the stored BOM is not changed


# -- schema validation --------------------------------------------------------


def _schema_errors(document, version="1.5"):
    """Errors of the official CycloneDX JSON schema (strict), or None."""
    import json

    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator

    validator = JsonStrictValidator(SchemaVersion.from_version(version))
    return validator.validate_str(json.dumps(document))


SCHEMA_BOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 1,
    "metadata": {"component": {"type": "application", "name": "App", "version": "1.0"}},
    "components": [
        {"type": "library", "bom-ref": "c1", "name": "lib-a", "version": "1.0",
         "purl": "pkg:npm/lib-a@1.0"},
        {"type": "library", "bom-ref": "ref-b", "name": "lib-b", "version": "2.0",
         "purl": "pkg:npm/lib-b@2.0"},
    ],
}


def test_the_documents_are_valid_cyclonedx():
    stray = {"uuid": "c9", "name": "lib-z", "version": "3.1", "purl": "pkg:npm/lib-z@3.1"}
    findings = [
        _finding(C1),
        _finding(C2),
        _finding(C1, "CVE-2026-2", "v2", aliases=[], severity="UNASSIGNED",
                 cvssV3BaseScore=None, cvssV3Vector=None),
        _finding(stray, "GHSA-aaaa-bbbb-cccc", "v3", source="GITHUB",
                 cvssV4BaseScore=8.7,
                 cvssV4Vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"),
    ]
    assessments = [
        parse_assessment("NOT_AFFECTED", ASSESSED, True),
        parse_assessment("EXPLOITABLE", "Reachable here.", False),
        parse_assessment("NOT_SET", "", False),
        parse_assessment("IN_TRIAGE", "Side note.\n\n--- [Team: General] "
                         "[State: IN_TRIAGE] [SSVC: ATTEND] ---\nLooking.", False),
    ]

    inventory = build_inventory(SCHEMA_BOM, findings)
    vdr = build_vdr(
        SCHEMA_BOM, findings, assessments,
        assessment_source="ACME PSIRT", property_prefix="acme",
        generated_at=NOW, tool_version="2.0.0",
    )

    assert _schema_errors(inventory) is None
    assert _schema_errors(vdr) is None
    # The validator does reject what the schema forbids.
    broken = {**vdr, "annotations": [{**vdr["annotations"][0], "annotator": {
        "organization": {"name": "Core"}, "individual": {"name": "bob"},
    }}]}
    assert _schema_errors(broken) is not None


def test_a_bom_of_an_older_specification_becomes_a_valid_1_5_document():
    old = {**SCHEMA_BOM, "specVersion": "1.4"}
    vdr = build_vdr(
        old, [_finding(C1)], [parse_assessment("NOT_AFFECTED", ASSESSED, False)],
        generated_at=NOW,
    )
    assert vdr["specVersion"] == "1.5" and _schema_errors(vdr) is None

