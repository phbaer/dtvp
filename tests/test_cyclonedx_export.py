"""CycloneDX inventory and VDR built from DTVP's records."""

import json
from datetime import UTC, datetime

from dtvp.assessment_model import parse_assessment
from dtvp.cyclonedx_export import (
    build_inventory,
    build_vdr,
    complete_findings,
    valid_property_prefix,
    valid_ticket_prefix,
)

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
        # The General assessment has no date here; the Core team's has.
        "lastUpdated": "2026-11-13T09:14:49.026000+00:00",
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
        {
            "name": "acme:historical_assessment",
            "value": '{"team": "Old", "state": "EXPLOITABLE", "text": "Outdated."}',
        },
    ]
    # One annotation per current team; General is the analysis itself and
    # historical blocks are a property, not an annotation.
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
    assert valid_ticket_prefix("SEC_OPS2")
    assert not valid_ticket_prefix("A-B") and not valid_ticket_prefix("1A")


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
        # The dates as Dependency-Track delivers them.
        _finding(C1, published="1777058234490", updated=1777144634000,
                 recommendation="Upgrade."),
        _finding(C2, published="1777058234490", updated=1777144634000,
                 recommendation="Upgrade."),
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
    assert vdr["vulnerabilities"][0]["published"] == "2026-04-24T19:17:14.490000+00:00"
    assert vdr["vulnerabilities"][0]["updated"] == "2026-04-25T19:17:14+00:00"
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


# -- gaps a consumer found ---------------------------------------------------

V4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"


def _entry(text, state="NOT_AFFECTED", finding=None, **options):
    document = _vdr([finding or _finding(C1)], [(state, text)], **options)
    [entry] = document["vulnerabilities"]
    return entry, document


def _property(entry, name):
    return [item["value"] for item in entry.get("properties", []) if item["name"] == name]


def _valid(document):
    """The findings and annotations of ``document`` in a BOM the schema accepts."""
    parts = {key: document[key] for key in ("vulnerabilities", "annotations") if key in document}
    return _schema_errors({**SCHEMA_BOM, **parts}) is None


def test_every_cvss_version_of_the_advisory_is_a_rating_with_its_score():
    # As the finding record has it: a CVSS 4 vector without a score, and
    # CVSS 3.1 with one. The severity of the advisory is the overall one.
    finding = _finding(
        C1, severity="HIGH", cvssV4Vector=V4, cvssV3BaseScore=7.5, cvssV3Vector=V31,
        cvssV2Vector="(AV:N/AC:L/Au:N/C:P/I:P/A:P)",
    )
    entry, document = _entry("", "NOT_SET", finding)

    assert entry["ratings"] == [
        {"source": {"name": "NVD"}, "score": 8.7, "severity": "high",
         "method": "CVSSv4", "vector": V4},
        {"source": {"name": "NVD"}, "score": 7.5, "severity": "high",
         "method": "CVSSv31", "vector": V31},
        {"source": {"name": "NVD"}, "score": 7.5, "severity": "high",
         "method": "CVSSv2", "vector": "(AV:N/AC:L/Au:N/C:P/I:P/A:P)"},
    ]
    assert all("score" in rating for rating in entry["ratings"] if "vector" in rating)
    assert _valid(document)


def test_a_rating_has_the_severity_of_its_own_score():
    finding = _finding(
        C1, severity="MEDIUM", cvssV3BaseScore=9.8,
        cvssV3Vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    )
    [rating] = _entry("", "NOT_SET", finding)[0]["ratings"]
    assert (rating["score"], rating["severity"]) == (9.8, "critical")

    # A vector nobody can read keeps its place, without an invented score.
    unreadable = _finding(C1, cvssV3BaseScore=None, cvssV3Vector="CVSS:3.1/AV:N")
    [rating] = _entry("", "NOT_SET", unreadable)[0]["ratings"]
    assert rating == {"source": {"name": "NVD"}, "method": "CVSSv31", "vector": "CVSS:3.1/AV:N"}


def test_the_complete_vulnerability_record_completes_a_finding():
    finding = _finding(
        C1, cvssV3BaseScore=None, cvssV3Vector=None, cvssV4Vector=V4, description="",
    )
    record = {
        "uuid": "v1", "vulnId": "CVE-2026-1", "source": "NVD",
        "cvssV3BaseScore": 7.5, "cvssV3Vector": V31, "cvssV4Vector": "ignored",
        "published": 1777058234490, "updated": 1777144634000,
        "recommendation": "Upgrade to 1.1.", "description": "From the record.",
    }
    by_id = {**record, "uuid": "another"}
    for records in ([record], [by_id]):
        [completed] = complete_findings([finding], records)
        vulnerability = completed["vulnerability"]
        assert vulnerability["cvssV4Vector"] == V4  # the finding's value is kept
        assert vulnerability["cvssV3BaseScore"] == 7.5
        assert vulnerability["recommendation"] == "Upgrade to 1.1."
        assert vulnerability["description"] == "From the record."
    assert "recommendation" not in finding["vulnerability"]  # not changed in place
    assert complete_findings([finding], []) == [finding]
    assert complete_findings([finding], [{"uuid": "other", "vulnId": "CVE-1"}]) == [finding]

    entry, _document = _entry("", "NOT_SET", completed)
    assert [rating["method"] for rating in entry["ratings"]] == ["CVSSv4", "CVSSv31"]
    assert entry["recommendation"] == "Upgrade to 1.1."


def test_published_and_updated_are_date_times():
    # Dependency-Track delivers milliseconds since 1970, as number or text.
    finding = _finding(C1, published="1777058234490", updated=1777144634000)
    entry, document = _entry("", "NOT_SET", finding)
    assert entry["published"] == "2026-04-24T19:17:14.490000+00:00"
    assert entry["updated"] == "2026-04-25T19:17:14+00:00"

    iso = _finding(C1, published="2026-04-24T19:17:14Z", updated="2026-04-24 21:17:14+02:00")
    entry, _ = _entry("", "NOT_SET", iso)
    assert entry["published"] == entry["updated"] == "2026-04-24T19:17:14+00:00"

    unreadable, _ = _entry("", "NOT_SET", _finding(C1, published="soon", updated=""))
    assert "published" not in unreadable and "updated" not in unreadable

    assert _valid(document)
    # The validation checks the format: the value DTVP wrote before fails.
    former = [{**document["vulnerabilities"][0], "published": "1777058234490"}]
    assert not _valid({"vulnerabilities": former})


def test_ticket_keys_in_the_texts_of_assessments_are_exported():
    text = (
        "Tracked in EXP-7, see also ABC-12 and CVE-2026-1.\n\n"
        "--- [Team: General] [State: EXPLOITABLE] [Assessed By: alice] ---\n"
        "Fix planned with EXP-2001 and EXP-1001.\n\n"
        "Former team assessment (Old; EXPLOITABLE; assessed by olaf):\nWas EXP-9.\n\n"
        "--- [Team: Core] [State: EXPLOITABLE] [Assessed By: bob] [Ticket: EXP-1001] ---\n"
        "Patch is SEC_OPS-5; not NEXP-3 or EXP-x.\n\n"
        "--- [Team: Gone] [State: EXPLOITABLE] [Historical: yes] ---\nEXP-8."
    )
    entry, document = _entry(text, "EXPLOITABLE", ticket_prefixes=["EXP", "SEC_OPS"])
    # The recorded ticket first, then what the texts mention, also those of
    # former and historical assessments: a ticket is about the vulnerability,
    # not about who owned the component. No key of another project.
    assert _property(entry, "dtvp:spr") == [
        "EXP-1001, EXP-2001, SEC_OPS-5, EXP-9, EXP-8, EXP-7"
    ]
    metadata = document["metadata"]["properties"]
    assert {"name": "dtvp:export_ticket_prefixes", "value": "EXP, SEC_OPS"} in metadata
    assert {"name": "dtvp:export_text_only_tickets", "value": "1"} in metadata

    # Without configured keys DTVP recognises none and says nothing about it.
    entry, document = _entry(text, "EXPLOITABLE")
    assert _property(entry, "dtvp:spr") == ["EXP-1001"]
    assert not any("ticket" in item["name"] for item in document["metadata"]["properties"])


def test_a_reviewer_named_inside_the_text_is_exported():
    text = (
        "--- [Team: General] [State: NOT_AFFECTED] [Justification: CODE_NOT_PRESENT] ---\n"
        "Not shipped.\n[Reviewed by: rita]\n[Assessed by: alice]"
    )
    entry, _ = _entry(text)
    assert _property(entry, "dtvp:reviewed_by") == ["rita"]
    assert _property(entry, "dtvp:assessed_by") == ["alice"]
    assert entry["analysis"]["detail"] == "Not shipped."

    legacy, _ = _entry("Not shipped. [Reviewed By: rita] [Rescored: 0.0]")
    assert _property(legacy, "dtvp:reviewed_by") == ["rita"]
    assert legacy["analysis"]["detail"] == "Not shipped."
    assert legacy["ratings"][-1]["justification"] == "Not shipped."


def test_an_assessment_without_a_team_names_no_team():
    text = (
        "--- [Team: General] [State: NOT_AFFECTED] [Assessed By: alice] ---\nReason.\n\n"
        "--- [Team: Unknown] [State: NOT_AFFECTED] [Assessed By: rita] "
        "[Date: 1794561289026] ---\nSee global assessment.\n\n"
        "--- [Team: Core] [State: NOT_AFFECTED] [Assessed By: bob] ---\n"
        "See global  assessment."
    )
    entry, document = _entry(text, unowned_teams=["unknown"])
    # A text that only points to the General assessment is no annotation; a
    # team the project has keeps its state.
    assert "annotations" not in document
    assert _property(entry, "dtvp:team_state") == ["Core=NOT_AFFECTED"]
    # Its state is exported without the name, keyed by the assessor.
    assert _property(entry, "dtvp:unassigned_state") == ["rita=NOT_AFFECTED"]
    assert "Unknown" not in str(document)
    assert _valid(document)

    own = (
        "--- [Team: Unknown] [State: EXPLOITABLE] [Assessed By: rita] "
        "[Date: 1794561289026] ---\nReachable.\n\n"
        "--- [Team: Core] [State: EXPLOITABLE] [Assessed By: bob] ---\nYes."
    )
    entry, document = _entry(own, "EXPLOITABLE", unowned_teams=["Unknown"])
    assert [item["annotator"] for item in document["annotations"]] == [
        {"individual": {"name": "rita"}},
        {"organization": {"name": "Core", "contact": [{"name": "bob"}]}},
    ]
    assert _property(entry, "dtvp:team_state") == ["Core=EXPLOITABLE"]
    assert _property(entry, "dtvp:unassigned_state") == ["rita=EXPLOITABLE"]
    assert "Unknown" not in str(document)
    assert _valid(document)

    anonymous = "--- [Team: Unknown] [State: EXPLOITABLE] ---\nReachable."
    entry, document = _entry(anonymous, "EXPLOITABLE", unowned_teams=["Unknown"])
    assert "annotations" not in document
    assert _property(entry, "dtvp:unassigned_assessment") == ["Reachable."]
    assert _property(entry, "dtvp:unassigned_state") == ["-=EXPLOITABLE"]
    assert "Unknown" not in str(document)
    assert _valid(document)

    # A project that has a team of this name keeps it.
    entry, document = _entry(own, "EXPLOITABLE")
    assert "Unknown=EXPLOITABLE" in _property(entry, "dtvp:team_state")
    assert _property(entry, "dtvp:unassigned_state") == []

    # Several names for no team: one state each, in block order.
    two = (
        "--- [Team: Unknown] [State: EXPLOITABLE] [Assessed By: rita] ---\nReachable.\n\n"
        "--- [Team: Core] [State: NOT_AFFECTED] [Assessed By: bob] ---\nNo.\n\n"
        "--- [Team: Nobody] [State: IN_TRIAGE] ---\nLooking."
    )
    entry, document = _entry(two, "EXPLOITABLE", unowned_teams=["Unknown", "Nobody"])
    assert _property(entry, "dtvp:unassigned_state") == ["rita=EXPLOITABLE", "-=IN_TRIAGE"]
    assert _property(entry, "dtvp:team_state") == ["Core=NOT_AFFECTED"]
    assert "Unknown" not in str(document) and "Nobody" not in str(document)
    assert _valid(document)


def test_the_state_of_an_assessment_without_a_team_pairs_with_its_text():
    # The block without an assessor comes first: block order alone would
    # pair its state with the assessor's annotation.
    text = (
        "--- [Team: Nobody] [State: IN_TRIAGE] ---\nLooking.\n\n"
        "--- [Team: Unknown] [State: EXPLOITABLE] [Assessed By: rita] ---\nReachable."
    )
    entry, document = _entry(text, "EXPLOITABLE", unowned_teams=["Unknown", "Nobody"])
    states = dict(
        value.split("=", 1) for value in _property(entry, "dtvp:unassigned_state")
    )
    texts = {
        item["annotator"]["individual"]["name"]: item["text"]
        for item in document["annotations"]
    }
    # The assessor's state goes with the assessor's annotation ...
    assert states["rita"] == "EXPLOITABLE" and texts["rita"] == "Reachable."
    # ... and the state without an assessor with the text without one.
    assert states["-"] == "IN_TRIAGE"
    assert _property(entry, "dtvp:unassigned_assessment") == ["Looking."]
    assert "Unknown" not in str(document) and "Nobody" not in str(document)
    assert _valid(document)


def test_findings_that_differ_in_the_state_without_a_team_are_separate_entries():
    def text(state):
        return (
            "--- [Team: General] [State: EXPLOITABLE] [Assessed By: alice] ---\nReason.\n\n"
            f"--- [Team: Unknown] [State: {state}] ---\nSee global assessment."
        )

    document = _vdr(
        [_finding(C1), _finding(C2)],
        [("EXPLOITABLE", text("EXPLOITABLE")), ("EXPLOITABLE", text("NOT_AFFECTED"))],
        unowned_teams=["Unknown"],
    )
    first, second = document["vulnerabilities"]
    assert (first["bom-ref"], second["bom-ref"]) == ("v1", "v1#2")
    assert _property(first, "dtvp:unassigned_state") == ["-=EXPLOITABLE"]
    assert _property(second, "dtvp:unassigned_state") == ["-=NOT_AFFECTED"]
    assert "Unknown" not in str(document)
    assert _valid(document)


def test_former_team_assessments_are_not_part_of_the_rationale():
    first = (
        "Former team assessment (TeamA; NOT_AFFECTED; justification "
        "CODE_NOT_REACHABLE; assessed by alice):\nNot reachable.\n\n"
        "CVSS 3.1: 7.5 -> 0.0"
    )
    second = "Former team assessment (TeamZ; NOT_AFFECTED; assessed by zoe)."
    text = (
        "[Rescored: 0.0] [Rescored Vector: " + VECTOR + "]\n\n"
        "--- [Team: General] [State: NOT_AFFECTED] [Assessed By: rita] ---\n"
        f"The parser is never called.\n\n{first}\n\n{second}"
    )
    entry, _ = _entry(text)
    assert entry["analysis"]["detail"] == "The parser is never called."
    assert entry["ratings"][-1]["justification"] == "The parser is never called."
    assert _property(entry, "dtvp:former_assessment") == [first, second]

    # Only former assessments: there is no rationale.
    only, _ = _entry(
        f"--- [Team: General] [State: NOT_AFFECTED] [Assessed By: rita] ---\n{second}"
    )
    assert "detail" not in only["analysis"]
    assert _property(only, "dtvp:former_assessment") == [second]


def test_the_repair_writes_the_former_team_note_the_export_recognises():
    from dtvp.bulk_workflows.assessment_repair import _former_team_note

    note = _former_team_note([
        {"team": "TeamA", "details": "Not reachable.",
         "tags": {"State": "NOT_AFFECTED", "Assessed By": "alice"}},
    ])
    entry, _ = _entry(
        "--- [Team: General] [State: NOT_AFFECTED] [Assessed By: rita] ---\n"
        f"Approved.\n\n{note}"
    )
    assert entry["analysis"]["detail"] == "Approved."
    assert _property(entry, "dtvp:former_assessment") == [note]


def test_a_rescoring_without_a_vector_says_so():
    entry, document = _entry("[Rescored: 5.3]\n\nLower in this product.")
    assert entry["ratings"][-1] == {
        "source": {"name": "DTVP"}, "score": 5.3, "severity": "medium",
        "method": "other", "justification": "Lower in this product.",
    }
    assert _valid(document)

    # A vector alone states its score.
    entry, _ = _entry(f"[Rescored Vector: {V31}]")
    own = entry["ratings"][-1]
    assert (own["score"], own["severity"], own["method"]) == (7.5, "high", "CVSSv31")


def test_the_general_assessment_has_its_date():
    text = (
        "--- [Team: General] [State: NOT_AFFECTED] [Assessed By: alice] "
        "[Date: 1794561289026] ---\nReason."
    )
    entry, document = _entry(text)
    assert entry["analysis"] == {
        "state": "not_affected", "detail": "Reason.",
        "lastUpdated": "2026-11-13T09:14:49.026000+00:00",
    }
    assert _valid(document)

    undated, _ = _entry("--- [Team: General] [State: NOT_AFFECTED] ---\nReason.")
    assert "lastUpdated" not in undated["analysis"]


# -- second reading by the consumer -----------------------------------------


def test_a_historical_team_assessment_is_exported_with_its_ticket():
    text = (
        "--- [Team: Core] [State: NOT_AFFECTED] [Assessed By: bob] "
        "[Date: 1794561289026] ---\nNot reachable.\n\n"
        "--- [Team: D-Web] [State: NOT_AFFECTED] [Assessed By: dana] "
        "[Reviewed By: rita] [Date: 1794000000000] "
        "[Justification: CODE_NOT_PRESENT] [Ticket: VP-4711] [Historical: yes] ---\n"
        "Not shipped in the web client."
    )
    entry, document = _entry(text)

    # The former owner's assessment is neither a live team state nor an
    # annotation, and it is not lost either.
    assert _property(entry, "dtvp:team_state") == ["Core=NOT_AFFECTED"]
    assert [item["annotator"]["organization"]["name"] for item in document["annotations"]] == ["Core"]
    (historical,) = _property(entry, "dtvp:historical_assessment")
    assert json.loads(historical) == {
        "team": "D-Web",
        "state": "NOT_AFFECTED",
        "justification": "CODE_NOT_PRESENT",
        "assessed_by": "dana",
        "reviewed_by": "rita",
        "date": "2026-11-06T21:20:00+00:00",
        "ticket": "VP-4711",
        "text": "Not shipped in the web client.",
    }
    # Its recorded ticket still tracks the vulnerability, with or without
    # configured ticket prefixes.
    assert _property(entry, "dtvp:spr") == ["VP-4711"]
    assert {"name": "dtvp:export_historical_assessments", "value": "1"} in (
        document["metadata"]["properties"]
    )
    assert _valid(document)

    _, plain = _entry("--- [Team: Core] [State: NOT_AFFECTED] ---\nNot reachable.")
    assert not any(
        "historical" in item["name"] for item in plain["metadata"]["properties"]
    )


def test_an_analysis_without_a_general_date_has_the_latest_team_date():
    text = (
        "--- [Team: Core] [State: NOT_AFFECTED] [Assessed By: bob] "
        "[Date: 1794561289026] ---\nNot reachable.\n\n"
        "--- [Team: Edge] [State: NOT_AFFECTED] [Assessed By: eve] "
        "[Date: 1794000000000] ---\nNot shipped.\n\n"
        "--- [Team: Old] [State: EXPLOITABLE] [Date: 1799999999999] "
        "[Historical: yes] ---\nOutdated."
    )
    entry, document = _entry(text)
    # No General assessment: the state comes from the teams, and so does the
    # date. A former owner's later date does not count.
    assert entry["analysis"]["lastUpdated"] == "2026-11-13T09:14:49.026000+00:00"
    assert _valid(document)

    # An undated General assessment beside dated teams.
    entry, _ = _entry(
        "--- [Team: General] [State: NOT_AFFECTED] ---\nReason.\n\n" + text
    )
    assert entry["analysis"]["lastUpdated"] == "2026-11-13T09:14:49.026000+00:00"

    # The General assessment's own date wins.
    entry, _ = _entry(
        "--- [Team: General] [State: NOT_AFFECTED] [Date: 1794000000000] ---\n"
        "Reason.\n\n" + text
    )
    assert entry["analysis"]["lastUpdated"] == "2026-11-06T21:20:00+00:00"

    # No date anywhere: none is stated.
    entry, _ = _entry("--- [Team: Core] [State: NOT_AFFECTED] ---\nNot reachable.")
    assert "lastUpdated" not in entry["analysis"]


def _timestamps(document):
    """The timestamp of each annotation, by its annotator's name."""
    return {
        (item["annotator"].get("organization") or item["annotator"]["individual"])["name"]:
            item["timestamp"]
        for item in document["annotations"]
    }


def test_an_undated_annotation_takes_the_date_of_the_assessment():
    undated_core = "--- [Team: Core] [State: NOT_AFFECTED] [Assessed By: bob] ---\nNot reachable."
    general = (
        "--- [Team: General] [State: NOT_AFFECTED] [Assessed By: alice] "
        "[Date: 1794561289026] ---\nReason.\n\n"
    )
    # A dated General assessment dates the team's undated annotation.
    entry, document = _entry(general + undated_core)
    assert _timestamps(document)["Core"] == entry["analysis"]["lastUpdated"] == (
        "2026-11-13T09:14:49.026000+00:00"
    )
    assert _property(entry, "dtvp:undated_annotation") == []
    # The date is the assessment's, not the team's own: the team is named.
    assert _property(entry, "dtvp:annotation_dated_by_assessment") == ["Core"]
    assert _valid(document)

    # Without a General assessment, the latest date of the live teams.
    edge = (
        "--- [Team: Edge] [State: NOT_AFFECTED] [Assessed By: eve] "
        "[Date: 1794000000000] ---\nNot shipped.\n\n"
    )
    entry, document = _entry(edge + undated_core)
    assert _timestamps(document) == {
        "Edge": "2026-11-06T21:20:00+00:00", "Core": "2026-11-06T21:20:00+00:00",
    }
    assert _property(entry, "dtvp:undated_annotation") == []
    # Another team's date is not Core's own; Edge has its own.
    assert _property(entry, "dtvp:annotation_dated_by_assessment") == ["Core"]
    assert _valid(document)

    # A dated team annotation keeps its own date, also beside a later General one.
    entry, document = _entry(general + edge)
    assert entry["analysis"]["lastUpdated"] == "2026-11-13T09:14:49.026000+00:00"
    assert _timestamps(document)["Edge"] == "2026-11-06T21:20:00+00:00"
    assert _property(entry, "dtvp:annotation_dated_by_assessment") == []
    assert _valid(document)

    # A former owner's later date is not the assessment's.
    historical = (
        "\n\n--- [Team: Old] [State: EXPLOITABLE] [Date: 1799999999999] "
        "[Historical: yes] ---\nOutdated."
    )
    entry, document = _entry(edge + undated_core + historical)
    assert _timestamps(document)["Core"] == "2026-11-06T21:20:00+00:00"
    assert _property(entry, "dtvp:undated_annotation") == []
    assert _valid(document)


def test_an_annotation_without_any_date_is_named():
    undated_core = "--- [Team: Core] [State: NOT_AFFECTED] [Assessed By: bob] ---\nNot reachable."
    entry, document = _entry(undated_core)
    # The schema requires a timestamp: the export time, and the vulnerability
    # says whose annotation has no date of its own.
    assert _timestamps(document)["Core"] == document["metadata"]["timestamp"] == NOW.isoformat()
    assert _property(entry, "dtvp:undated_annotation") == ["Core"]
    assert _property(entry, "dtvp:annotation_dated_by_assessment") == []
    assert "lastUpdated" not in entry["analysis"]
    assert _valid(document)
    assert _schema_errors({**SCHEMA_BOM, "specVersion": "1.6", **{
        key: document[key] for key in ("vulnerabilities", "annotations")
    }}, "1.6") is None

    # Without a team, the assessor is named, never the fallback team name.
    unowned = (
        "--- [Team: Unknown] [State: EXPLOITABLE] [Assessed By: rita] ---\nReachable."
    )
    entry, document = _entry(unowned, "EXPLOITABLE", unowned_teams=["Unknown"])
    assert _property(entry, "dtvp:undated_annotation") == ["rita"]
    assert _timestamps(document)["rita"] == NOW.isoformat()
    assert "Unknown" not in str(document)
    assert _valid(document)

    # The property has the configured prefix.
    entry, document = _entry(undated_core, property_prefix="acme")
    assert _property(entry, "acme:undated_annotation") == ["Core"]
    assert _property(entry, "dtvp:undated_annotation") == []
    assert _valid(document)

    # Without an analysis, a General date still dates the annotation.
    dated_general = (
        "--- [Team: General] [State: NOT_SET] [Date: 1794561289026] ---\n\n"
        + undated_core
    )
    entry, document = _entry(dated_general, "NOT_SET")
    assert "analysis" not in entry
    assert _timestamps(document)["Core"] == "2026-11-13T09:14:49.026000+00:00"
    assert _property(entry, "dtvp:undated_annotation") == []
    assert _valid(document)


def test_the_document_names_its_property_prefix():
    _, document = _entry("", "NOT_SET", property_prefix="acme")
    assert {"name": "acme:export_property_prefix", "value": "acme"} in (
        document["metadata"]["properties"]
    )


# -- the report names its inventory -----------------------------------------


def test_the_same_inventory_has_the_same_serial_number_in_every_export():
    first = build_inventory({**BOM, "serialNumber": "urn:uuid:" + "1" * 8 + "-1111-4111-8111-" + "1" * 12})
    # Dependency-Track gives each export another serial number and time, and
    # may list the components in another order.
    again = build_inventory({
        **BOM,
        "serialNumber": "urn:uuid:" + "2" * 8 + "-2222-4222-8222-" + "2" * 12,
        "metadata": {**BOM["metadata"], "timestamp": "2026-11-19T08:00:00Z"},
        "components": list(reversed(BOM["components"])),
    })
    assert first["serialNumber"] == again["serialNumber"]
    assert first["serialNumber"].startswith("urn:uuid:")
    assert first["version"] == again["version"] == 1

    # Another content is another BOM.
    changed = build_inventory({
        **BOM,
        "components": [*BOM["components"], {"bom-ref": "c9", "name": "lib-z", "version": "9"}],
    })
    assert changed["serialNumber"] != first["serialNumber"]
    other_product = build_inventory({
        **BOM, "metadata": {"component": {"name": "App", "version": "2.0"}},
    })
    assert other_product["serialNumber"] != first["serialNumber"]


def test_the_serial_number_does_not_depend_on_the_property_prefix():
    unknown = {"uuid": "c7", "name": "lib-x", "version": "7.0"}
    findings = [_finding(unknown)]
    default = build_inventory(BOM, findings)
    prefixed = build_inventory(BOM, findings, property_prefix="acme")
    # The added component is part of the inventory, its mark's name is not.
    assert default["serialNumber"] == prefixed["serialNumber"]
    assert default["serialNumber"] != build_inventory(BOM)["serialNumber"]


def test_the_vdr_names_the_inventory_it_describes():
    findings = [_finding(C1), _finding({"uuid": "c7", "name": "lib-x", "version": "7.0"})]
    inventory = build_inventory(BOM, findings)
    first = _vdr(findings, [("NOT_SET", ""), ("NOT_SET", "")])
    second = _vdr(findings, [("EXPLOITABLE", "Reachable."), ("NOT_SET", "")])

    link = "urn:cdx:" + inventory["serialNumber"].removeprefix("urn:uuid:") + "/1"
    for document in (first, second):
        assert document["externalReferences"] == [
            {"type": "bom", "url": link, "comment": "The inventory this report describes"}
        ]
        assert {"name": "dtvp:export_inventory", "value": link} in (
            document["metadata"]["properties"]
        )
        assert _valid(document)
        # The reference, the serial number and the version themselves are
        # what the schema accepts (a BOM-Link as the URL of a ``bom``).
        assert _schema_errors({
            **SCHEMA_BOM,
            **{key: document[key] for key in ("serialNumber", "version", "externalReferences")},
        }) is None
    assert _schema_errors({
        **SCHEMA_BOM, "serialNumber": inventory["serialNumber"], "version": inventory["version"],
    }) is None
    # A malformed link is refused, so the check above is a real one.
    assert _schema_errors({
        **SCHEMA_BOM, "externalReferences": [{"type": "bom", "url": "urn:cdx:not a link"}],
    }) is not None
    # Each report is its own document; a new assessment does not change the
    # inventory it points at.
    assert first["serialNumber"] != second["serialNumber"]
    assert inventory["serialNumber"] not in (first["serialNumber"], second["serialNumber"])


# --- The analysis response ---------------------------------------------------

_GENERAL_EXPLOITABLE = (
    "--- [Team: General] [State: EXPLOITABLE] [Assessed By: alice] "
    "[Justification: NOT_SET] ---\nReachable from the upload handler."
)


def test_the_response_is_exported_as_analysis_response():
    import pytest

    for stored, exported in [
        ("UPDATE", "update"),
        ("ROLLBACK", "rollback"),
        ("WORKAROUND_AVAILABLE", "workaround_available"),
        ("WILL_NOT_FIX", "will_not_fix"),
        ("CAN_NOT_FIX", "can_not_fix"),
    ]:
        entry, document = _entry(
            f"[Response: {stored}]\n\n{_GENERAL_EXPLOITABLE}", state="EXPLOITABLE"
        )
        assert entry["analysis"]["response"] == [exported]
        # The tag is the field, never part of the rationale.
        assert entry["analysis"]["detail"] == "Reachable from the upload handler."
        assert "Response" not in json.dumps(document)
        assert _valid(document)

    entry, document = _entry(_GENERAL_EXPLOITABLE, state="EXPLOITABLE")
    assert "response" not in entry["analysis"]
    assert _valid(document)

    # The schema check is strict: a value outside CycloneDX's list fails it.
    entry, document = _entry(
        f"[Response: UPDATE]\n\n{_GENERAL_EXPLOITABLE}", state="EXPLOITABLE"
    )
    entry["analysis"]["response"] = ["maybe_later"]
    assert not _valid(document)
    with pytest.raises(KeyError):
        _entry("[Response: UPDATE]", state="NOT_SET")[0]["analysis"]


def test_a_response_beside_a_rescoring_and_free_text_only():
    entry, document = _entry(
        f"[Rescored: 2.5] [Rescored Vector: {VECTOR}] [Response: WORKAROUND_AVAILABLE]"
        "\n\nDisable the endpoint.",
        state="EXPLOITABLE",
    )
    assert entry["analysis"] == {
        "state": "exploitable",
        "response": ["workaround_available"],
        "detail": "Disable the endpoint.",
    }
    assert _valid(document)


def test_findings_that_differ_only_in_the_response_are_separate_entries():
    document = _vdr(
        [_finding(C1), _finding(C2)],
        [
            ("EXPLOITABLE", f"[Response: UPDATE]\n\n{_GENERAL_EXPLOITABLE}"),
            ("EXPLOITABLE", f"[Response: WILL_NOT_FIX]\n\n{_GENERAL_EXPLOITABLE}"),
        ],
    )
    first, second = document["vulnerabilities"]
    assert (first["bom-ref"], second["bom-ref"]) == ("v1", "v1#2")
    assert first["analysis"]["response"] == ["update"]
    assert second["analysis"]["response"] == ["will_not_fix"]
    assert (first["affects"], second["affects"]) == ([{"ref": "c1"}], [{"ref": "ref-b"}])
    assert _valid(document)

    # One with and one without a response differ as well; equal ones are one.
    mixed = _vdr(
        [_finding(C1), _finding(C2)],
        [
            ("EXPLOITABLE", f"[Response: UPDATE]\n\n{_GENERAL_EXPLOITABLE}"),
            ("EXPLOITABLE", _GENERAL_EXPLOITABLE),
        ],
    )
    assert len(mixed["vulnerabilities"]) == 2
    same = _vdr(
        [_finding(C1), _finding(C2)],
        [("EXPLOITABLE", f"[Response: UPDATE]\n\n{_GENERAL_EXPLOITABLE}")] * 2,
    )
    assert len(same["vulnerabilities"]) == 1


# -- recommendation from fixed versions ---------------------------------------

PA = {"uuid": "c1", "name": "lib-a", "version": "1.0", "purl": "pkg:npm/lib-a@1.0"}
PB = {"uuid": "ref-b", "name": "lib-b", "version": "2.0", "purl": "pkg:npm/lib-b@2.0"}
READ_AT = "2026-11-17T08:00:00+00:00"


def _ranges(*entries, status="read", read_at=READ_AT):
    return {"status": status, "payload": list(entries), "vuln_updated": "",
            "read_at": read_at, "attempted_at": read_at}


def _excluding(package, end, *sources, start=None):
    entry = {"identityType": "PURL", "identity": f"pkg:npm/{package}",
             "versionType": "RANGE", "versionEndExcluding": end, "sources": list(sources)}
    if start:
        entry["versionStartIncluding"] = start
    return entry


def _metadata(document):
    return {item["name"]: item["value"] for item in document["metadata"]["properties"]}


def test_a_recommendation_is_derived_from_the_fixed_version():
    fixed = {("NVD", "CVE-2026-1"): _ranges(
        _excluding("lib-a", "1.2.3", "GITHUB", "OSV"),
        _excluding("lib-a", "2.0.1", "GITHUB", start="2.0.0"),
    )}
    entry, document = _entry("", "NOT_SET", _finding(PA), fixed_versions=fixed)

    assert entry["recommendation"] == (
        "Upgrade lib-a to 1.2.3 or later. Later versions are affected too: >=2.0.0 <2.0.1."
    )
    assert _property(entry, "dtvp:recommendation_source") == ["fixed_version"]
    assert _property(entry, "dtvp:recommendation_fixed_by") == ["GITHUB", "OSV"]
    metadata = _metadata(document)
    assert metadata["dtvp:export_derived_recommendations"] == "1"
    assert metadata["dtvp:export_fixed_versions_read_at"] == READ_AT
    assert "dtvp:export_fixed_versions_unread" not in metadata
    assert _valid(document)


def test_the_recommendation_dependency_track_has_is_kept():
    fixed = {("NVD", "CVE-2026-1"): _ranges(_excluding("lib-a", "1.2.3", "GITHUB"))}
    entry, document = _entry(
        "", "NOT_SET", _finding(PA, recommendation="Apply the vendor patch."),
        fixed_versions=fixed,
    )
    assert entry["recommendation"] == "Apply the vendor patch."
    assert _property(entry, "dtvp:recommendation_source") == ["advisory"]
    assert _property(entry, "dtvp:recommendation_fixed_by") == []
    assert _metadata(document)["dtvp:export_derived_recommendations"] == "0"
    assert _valid(document)


def test_without_a_fix_there_is_no_recommendation():
    fixed = {("NVD", "CVE-2026-1"): _ranges(
        {"identityType": "PURL", "identity": "pkg:npm/lib-a", "versionType": "RANGE",
         "versionEndIncluding": "1.0"},
    )}
    entry, document = _entry("", "NOT_SET", _finding(PA), fixed_versions=fixed)
    assert "recommendation" not in entry
    assert _property(entry, "dtvp:recommendation_source") == []
    assert _metadata(document)["dtvp:export_derived_recommendations"] == "0"
    assert _valid(document)


def test_several_affected_components_have_one_sentence_each():
    fixed = {("NVD", "CVE-2026-1"): _ranges(
        _excluding("lib-b", "2.1", "OSV"), _excluding("lib-a", "1.1", "GITHUB"),
    )}
    document = _vdr([_finding(PB), _finding(PA)], [("NOT_SET", "")] * 2,
                    fixed_versions=fixed)
    [entry] = document["vulnerabilities"]
    assert entry["affects"] == [{"ref": "ref-b"}, {"ref": "c1"}]
    # Sorted by component name.
    assert entry["recommendation"] == (
        "Upgrade lib-a to 1.1 or later. Upgrade lib-b to 2.1 or later."
    )
    assert _property(entry, "dtvp:recommendation_fixed_by") == ["GITHUB", "OSV"]
    assert _valid(document)


def test_the_document_counts_derived_and_unread_entries():
    fixed = {
        ("NVD", "CVE-2026-1"): _ranges(_excluding("lib-a", "1.1", "GITHUB")),
        ("NVD", "CVE-2026-3"): _ranges(read_at="2026-11-10T00:00:00+00:00"),
        # Failed before any good read: still unread.
        ("NVD", "CVE-2026-4"): {"status": "failed", "payload": None, "vuln_updated": None,
                                "read_at": READ_AT, "attempted_at": READ_AT},
    }
    findings = [
        _finding(PA),
        _finding(PA, "CVE-2026-2", "v2"),  # never read
        _finding(PA, "CVE-2026-3", "v3"),  # read, nothing for lib-a
        _finding(PA, "CVE-2026-4", "v4"),
        _finding(PA, "CVE-2026-5", "v5", recommendation="Upgrade."),  # not needed
        # Trivy's patched versions, without ranges: a hint only.
        _finding(PB, "CVE-2026-6", "v6", patchedVersions="2.0.4"),
    ]
    document = _vdr(findings, [("NOT_SET", "")] * len(findings), fixed_versions=fixed)
    metadata = _metadata(document)
    assert metadata["dtvp:export_derived_recommendations"] == "1"
    assert metadata["dtvp:export_fixed_versions_unread"] == "3"
    assert metadata["dtvp:export_fixed_versions_read_at"] == "2026-11-10T00:00:00+00:00"
    trivy = next(e for e in document["vulnerabilities"] if e["id"] == "CVE-2026-6")
    assert "recommendation" not in trivy
    assert _property(trivy, "dtvp:recommendation_source") == []
    assert _property(trivy, "dtvp:patched_versions") == ["2.0.4"]
    assert _valid(document)

    # Without looked-up ranges nothing counts as unread.
    without = _vdr(findings, [("NOT_SET", "")] * len(findings))
    assert "dtvp:export_fixed_versions_unread" not in _metadata(without)
    assert _metadata(without)["dtvp:export_derived_recommendations"] == "0"


def test_a_whole_vdr_with_derived_recommendations_is_valid_and_keeps_the_inventory():
    findings = [
        _finding(PA), _finding(PB),
        _finding(PA, "GHSA-aaaa-bbbb-cccc", "v3", source="GITHUB"),
    ]
    assessments = [
        parse_assessment("NOT_AFFECTED", ASSESSED, False),
        parse_assessment("EXPLOITABLE", "Reachable here.", False),
        parse_assessment("NOT_SET", "", False),
    ]
    fixed = {
        ("NVD", "CVE-2026-1"): _ranges(
            _excluding("lib-a", "1.1", "NVD"), _excluding("lib-b", "2.1", "OSV"),
        ),
        ("GITHUB", "GHSA-aaaa-bbbb-cccc"): _ranges(_excluding("lib-a", "1.0.5", "GITHUB")),
    }
    plain = build_vdr(SCHEMA_BOM, findings, assessments, generated_at=NOW)
    derived = build_vdr(SCHEMA_BOM, findings, assessments, generated_at=NOW,
                        fixed_versions=fixed)

    assert _schema_errors(derived) is None
    assert [entry.get("recommendation") for entry in derived["vulnerabilities"]] == [
        "Upgrade lib-a to 1.1 or later.",
        "Upgrade lib-b to 2.1 or later.",
        "Upgrade lib-a to 1.0.5 or later.",
    ]
    # The inventory does not change with the recommendation.
    assert _metadata(derived)["dtvp:export_inventory"] == _metadata(plain)["dtvp:export_inventory"]
    assert build_inventory(SCHEMA_BOM, findings)["serialNumber"] == (
        _metadata(derived)["dtvp:export_inventory"].removeprefix("urn:cdx:")
        .removesuffix("/1").join(["urn:uuid:", ""])
    )
