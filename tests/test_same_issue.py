"""Findings that are probably the same issue under two ids no source links
(CVE-2026-65901 and GHSA-x4vx-rjvf-j5p4 on dompurify): proposed by their
text alone (never by range and CWE, which matched different issues of one
package); applied and exported only once a person confirmed them."""

from unittest.mock import patch

from dtvp import main
from dtvp.cyclonedx_export import build_vdr
from dtvp.dt_client import DTClient
from dtvp.same_issue import (
    REASON_DESCRIPTION,
    SameIssueIndex,
    confirmed_pairs,
    description_key,
    facts_by_uuid,
    same_issue_reason,
)
from tests.test_export import _finding, queued  # noqa: F401

TEXT = (
    "DOMPurify before 3.2.8 allows mutation XSS through a crafted SVG element "
    "when IN_PLACE sanitization is used."
)


def _record(uuid, vuln_id, description=TEXT, cwes=(), source=None):
    return {
        "uuid": uuid, "vulnId": vuln_id, "description": description,
        "cwes": [{"cweId": cwe} for cwe in cwes], **({"source": source} if source else {}),
    }


def _row(component, vulnerability, vuln_id, status="reported", **extra):
    return {
        "component_uuid": component, "vulnerability_uuid": vulnerability,
        "vuln_id": vuln_id, "status": status, "component_name": "dompurify",
        "component_version": "3.2.7", "component_purl": "pkg:npm/dompurify@3.2.7",
        **extra,
    }


# -- matching ------------------------------------------------------------------


def test_the_description_key_ignores_case_spacing_punctuation_and_ids():
    left = description_key(f"CVE-2026-65901: {TEXT}", ["CVE-2026-65901"])
    right = description_key(f"  {TEXT.upper()}  (GHSA-x4vx-rjvf-j5p4)", ["GHSA-x4vx-rjvf-j5p4"])
    assert left == right
    assert description_key("Too short.") is None
    assert description_key("") is None


def test_two_records_without_aliases_and_the_same_text_are_the_same_issue():
    facts = facts_by_uuid(
        DTClient.vulnerability_facts,
        [{"vulnerability": _record("v-cve", "CVE-2026-65901")}],
        [_record("v-ghsa", "GHSA-x4vx-rjvf-j5p4")],
    )
    assert same_issue_reason(facts["v-cve"], facts["v-ghsa"]) == REASON_DESCRIPTION
    other = facts_by_uuid(
        DTClient.vulnerability_facts,
        [_record("v-other", "GHSA-zzzz-zzzz-zzzz", "A different flaw in another place of the parser.")],
    )
    assert same_issue_reason(facts["v-cve"], other["v-other"]) is None


def test_the_same_range_and_cwe_without_the_same_text_is_no_match():
    """CVE-2026-59898 and CVE-2026-59900 on every netty 4.1.133.Final package:
    same affected range, same CWE, different issues."""
    facts = facts_by_uuid(
        DTClient.vulnerability_facts,
        [
            _record("v-a", "CVE-2026-59898", "Netty HTTP/2 codec allows a flood of RST frames to exhaust memory.", cwes=(400,)),
            _record("v-b", "CVE-2026-59900", "Netty resolver accepts oversized DNS answers and loops on compression pointers.", cwes=(400,)),
        ],
    )
    assert same_issue_reason(facts["v-a"], facts["v-b"]) is None
    rows = {
        ("c", "v-a"): _row("c", "v-a", "CVE-2026-59898", component_name="netty-codec-http2"),
        ("c", "v-b"): _row("c", "v-b", "CVE-2026-59900", component_name="netty-codec-http2"),
    }
    states = {"v-a": "EXPLOITABLE", "v-b": "NOT_AFFECTED"}
    assert SameIssueIndex(rows, facts).disagreements(
        lambda row: {"analysisState": states[row["vulnerability_uuid"]]}
    ) == []


def test_a_description_several_ids_share_on_a_component_is_a_template():
    boilerplate = "This vulnerability affects the package and may allow an attacker to cause harm."
    facts = facts_by_uuid(
        DTClient.vulnerability_facts,
        [_record(f"v-{n}", f"PYSEC-2026-{n}", boilerplate) for n in (1, 2, 3)],
    )
    rows = {
        ("c", f"v-{n}"): _row("c", f"v-{n}", f"PYSEC-2026-{n}") for n in (2, 3)
    }
    gone = _row("c", "v-1", "PYSEC-2026-1", status="gone")
    rows[("c", "v-1")] = gone
    states = {"v-1": "EXPLOITABLE", "v-2": "NOT_AFFECTED", "v-3": "EXPLOITABLE"}
    index = SameIssueIndex(rows, facts)
    assert index.match(gone) is None
    assert index.disagreements(lambda row: {"analysisState": states[row["vulnerability_uuid"]]}) == []
    # Two ids sharing it are still one issue.
    del rows[("c", "v-3")]
    assert SameIssueIndex(rows, facts).match(gone)[1] == REASON_DESCRIPTION


def test_the_index_matches_on_the_component_or_its_recreation_and_skips_aliases():
    facts = facts_by_uuid(
        DTClient.vulnerability_facts,
        [_record("v-cve", "CVE-2026-65901"), _record("v-ghsa", "GHSA-x4vx-rjvf-j5p4"),
         _record("v-alias", "GHSA-aaaa-bbbb-cccc")],
    )
    gone = _row("c-old", "v-cve", "CVE-2026-65901", status="gone")
    rows = {
        ("c-old", "v-cve"): gone,
        # The recreated component: same package URL and version, new UUID.
        ("c-new", "v-ghsa"): _row("c-new", "v-ghsa", "GHSA-x4vx-rjvf-j5p4"),
    }
    match = SameIssueIndex(rows, facts).match(gone)
    assert match is not None and match[0]["vuln_id"] == "GHSA-x4vx-rjvf-j5p4"
    assert match[1] == REASON_DESCRIPTION
    # Another version of the package is another component.
    other_version = {("c-new", "v-ghsa"): _row("c-new", "v-ghsa", "GHSA-x4vx-rjvf-j5p4",
                                               component_version="3.2.9",
                                               component_purl="pkg:npm/dompurify@3.2.9")}
    assert SameIssueIndex({**other_version, ("c-old", "v-cve"): gone}, facts).match(gone) is None
    # A real alias is the alias view's, not a guess.
    aliases = {"CVE-2026-65901": {"GHSA-X4VX-RJVF-J5P4"}}
    assert SameIssueIndex(rows, facts, aliases=aliases).match(gone) is None


def test_reported_pairs_that_disagree_are_listed():
    facts = facts_by_uuid(
        DTClient.vulnerability_facts,
        [_record("v-cve", "CVE-2026-65913"), _record("v-ghsa", "GHSA-v9jr-rg53-9pgp")],
    )
    rows = {
        ("c", "v-cve"): _row("c", "v-cve", "CVE-2026-65913"),
        ("c", "v-ghsa"): _row("c", "v-ghsa", "GHSA-v9jr-rg53-9pgp"),
    }
    states = {"v-cve": "NOT_AFFECTED", "v-ghsa": "EXPLOITABLE"}
    [pair] = SameIssueIndex(rows, facts).disagreements(
        lambda row: {"analysisState": states[row["vulnerability_uuid"]]}
    )
    assert pair["reason"] == REASON_DESCRIPTION
    assert [item["state"] for item in pair["findings"]] == ["NOT_AFFECTED", "EXPLOITABLE"]
    states["v-ghsa"] = "NOT_AFFECTED"
    assert SameIssueIndex(rows, facts).disagreements(
        lambda row: {"analysisState": states[row["vulnerability_uuid"]]}
    ) == []


# -- export ---------------------------------------------------------------------


def _vdr(same_issue_as):
    finding = {
        "component": {"uuid": "c", "name": "dompurify", "version": "3.2.7",
                      "purl": "pkg:npm/dompurify@3.2.7"},
        "vulnerability": {"uuid": "v-ghsa", "vulnId": "GHSA-x4vx-rjvf-j5p4", "source": "GITHUB"},
    }
    fields = {
        "state": "NOT_AFFECTED", "suppressed": False, "pending_review": False,
        "rescored_score": None, "rescored_vector": None, "free_text": "", "teams": [],
    }
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.5",
           "components": [{"bom-ref": "c", "name": "dompurify", "version": "3.2.7"}]}
    return build_vdr(bom, [finding], [fields], same_issue_as=same_issue_as)


def test_only_a_confirmed_match_is_exported_and_never_as_a_reference():
    [entry] = _vdr(None)["vulnerabilities"]
    assert not any(p["name"].endswith(":same_issue_as") for p in entry.get("properties", []))
    [entry] = _vdr({("c", "v-ghsa"): {"CVE-2026-65901"}})["vulnerabilities"]
    assert {"name": "dtvp:same_issue_as", "value": "CVE-2026-65901"} in entry["properties"]
    assert "references" not in entry


def test_confirmed_pairs_point_both_ways():
    rows = [
        _row("c-old", "v-cve", "CVE-2026-65901", status="gone",
             same_issue_component_uuid="c", same_issue_vulnerability_uuid="v-ghsa",
             same_issue_confirmed_by="rita"),
        _row("c", "v-ghsa", "GHSA-x4vx-rjvf-j5p4"),
        _row("c", "v-unconfirmed", "CVE-2026-1", same_issue_component_uuid="c",
             same_issue_vulnerability_uuid="v-ghsa"),
    ]
    assert confirmed_pairs(rows) == {
        ("c-old", "v-cve"): {"GHSA-x4vx-rjvf-j5p4"},
        ("c", "v-ghsa"): {"CVE-2026-65901"},
    }


# -- through the API ------------------------------------------------------------


def _with_text(item):
    item = {**item, "vulnerability": {**item["vulnerability"], "description": TEXT}}
    return item


def _advisory_without_alias():
    """The GHSA of CVE-2026-0001 as the source has it: no alias, same text."""
    return {
        "uuid": "finding-g",
        "vulnerability": {"vulnId": "GHSA-x4vx-rjvf-j5p4", "uuid": "vuln-g",
                          "severity": "HIGH", "description": TEXT},
        "component": {"name": "library-a", "uuid": "component-1", "version": "2.0"},
        "analysis": {},
    }


async def _gone_cve_and_its_advisory(queued):  # noqa: F811
    queued.get_analysis.return_value = None
    queued.get_vulnerabilities.return_value = [_with_text(_finding(1)), _finding(2)]
    await main.cache_manager.get_vulnerabilities(queued, "p1", refresh=True)
    queued.get_vulnerabilities.return_value = [_advisory_without_alias(), _finding(2)]
    await main.cache_manager.get_vulnerabilities(queued, "p1", refresh=True)
    # The stored vulnerability records still describe the gone CVE.
    main.cache_manager._save_project_cache(
        main.cache_manager._project_vulns_path("p1"),
        [_record("vuln-1", "CVE-2026-0001"), _record("vuln-g", "GHSA-x4vx-rjvf-j5p4")],
        project_uuid="p1",
    )


REQUEST = {"project_uuid": "p1", "component_uuid": "component-1", "vulnerability_uuid": "vuln-1"}
CONFIRM = {**REQUEST, "other_component_uuid": "component-1", "other_vulnerability_uuid": "vuln-g"}
APPLY = {**REQUEST, "alias_vulnerability_uuid": "vuln-g"}


async def test_a_gone_cve_proposes_its_unlinked_advisory_applied_only_after_confirming(
    client, queued  # noqa: F811
):
    await _gone_cve_and_its_advisory(queued)

    [finding] = client.get("/api/project/p1/gone-findings").json()["findings"]
    assert finding["alias"] is None
    guess = finding["same_issue"]
    assert (guess["vuln_id"], guess["reason"], guess["proposal"]) == (
        "GHSA-x4vx-rjvf-j5p4", REASON_DESCRIPTION, "copy"
    )
    assert guess["confirmed_by"] is None

    # Not applied as long as nobody confirmed it.
    assert client.post("/api/gone-findings/apply-to-alias", json=APPLY).status_code == 409
    assert main.cache_manager.get_assessment_overlay("p1", "component-1", "vuln-g") is None
    with patch("dtvp.main.get_user_role", return_value="ANALYST"):
        assert client.post("/api/gone-findings/same-issue", json=CONFIRM).status_code == 403

    confirmed = client.post("/api/gone-findings/same-issue", json=CONFIRM)
    assert confirmed.status_code == 200, confirmed.text
    assert confirmed.json()["reason"] == REASON_DESCRIPTION
    [finding] = client.get("/api/project/p1/gone-findings").json()["findings"]
    assert finding["same_issue"]["confirmed_by"] == "rita"

    applied = client.post("/api/gone-findings/apply-to-alias", json=APPLY)
    assert applied.status_code == 200, applied.text
    record = main.cache_manager.get_assessment_overlay("p1", "component-1", "vuln-g")
    assert record["analysisState"] == "NOT_AFFECTED"
    assert record["analysisDetails"].rstrip().endswith("[Status: Pending Review]")
    history = main.cache_manager.get_assessment_history("p1", "component-1", "vuln-g")
    assert history[-1]["origin"] == "carried-over-by-same-issue"

    # Withdrawn: no longer applicable.
    withdrawn = client.post("/api/gone-findings/same-issue", json={**CONFIRM, "confirmed": False})
    assert withdrawn.json()["changed"] is True
    assert client.post("/api/gone-findings/apply-to-alias", json=APPLY).status_code == 409


async def test_only_a_proposed_match_can_be_confirmed(client, queued):  # noqa: F811
    await _gone_cve_and_its_advisory(queued)

    # CVE-2026-0002 is on another component and has another text.
    unrelated = client.post("/api/gone-findings/same-issue", json={
        **REQUEST, "other_component_uuid": "component-2", "other_vulnerability_uuid": "vuln-2",
    })
    assert unrelated.status_code == 409
    unknown = client.post("/api/gone-findings/same-issue", json={
        **CONFIRM, "vulnerability_uuid": "vuln-nothing",
    })
    assert unknown.status_code == 404


async def test_a_confirmed_match_is_exported_on_the_reported_entry(client, queued):  # noqa: F811
    await _gone_cve_and_its_advisory(queued)
    assert client.post("/api/gone-findings/same-issue", json=CONFIRM).status_code == 200
    rows = main.cache_manager.finding_lifecycle.presence("p1")
    assert confirmed_pairs(rows.values())[("component-1", "vuln-g")] == {"CVE-2026-0001"}

    queued.get_bom.return_value = {
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "components": [
            {"bom-ref": "component-1", "name": "library-a", "version": "2.0"},
            {"bom-ref": "component-2", "name": "library-a", "version": "2.0"},
        ],
        "dependencies": [],
    }
    document = await main.cache_manager.export_cyclonedx(
        queued, "p1", "vdr", assessment_source="dtvp", property_prefix="dtvp",
    )
    entries = {entry["id"]: entry for entry in document["vulnerabilities"]}
    properties = {p["name"]: p["value"] for p in entries["GHSA-x4vx-rjvf-j5p4"]["properties"]}
    assert properties["dtvp:same_issue_as"] == "CVE-2026-0001"
    assert "references" not in entries["GHSA-x4vx-rjvf-j5p4"]
    assert not any(
        p["name"] == "dtvp:same_issue_as" for p in entries["CVE-2026-0002"].get("properties", [])
    )


# -- a gone finding whose component River never knew ------------------------------


def _unknown(component, vulnerability, vuln_id):
    """A row made for a record from before tracking: no component facts."""
    return {
        "component_uuid": component, "vulnerability_uuid": vulnerability,
        "vuln_id": vuln_id, "status": "gone",
    }


def test_a_gone_finding_on_an_unknown_component_proposes_the_same_vulnerability():
    from dtvp.same_issue import REASON_UNKNOWN_COMPONENT

    rows = {
        ("c-old", "v1"): _unknown("c-old", "v1", "CVE-2024-28863"),
        ("c-tar", "v1"): {**_row("c-tar", "v1", "CVE-2024-28863"), "component_name": "tar"},
        ("c-other", "v2"): _row("c-other", "v2", "CVE-2026-1"),
    }
    index = SameIssueIndex(rows, {})
    other, reason = index.match(rows[("c-old", "v1")])
    assert (other["component_uuid"], reason) == ("c-tar", REASON_UNKNOWN_COMPONENT)
    # Only for a gone row without component facts, never between reported
    # findings, never for another vulnerability.
    known = {**rows[("c-old", "v1")], "component_name": "tar", "component_purl": "pkg:npm/tar@1.0"}
    assert index.reason(known, rows[("c-tar", "v1")]) is None
    assert index.reason(rows[("c-tar", "v1")], rows[("c-tar", "v1")]) is None
    assert index.reason(rows[("c-old", "v1")], rows[("c-other", "v2")]) is None
    # Confirmed, it names nothing in the export: it is the same id.
    confirmed = {**rows[("c-old", "v1")], "same_issue_component_uuid": "c-tar",
                 "same_issue_vulnerability_uuid": "v1", "same_issue_confirmed_by": "rita"}
    assert confirmed_pairs([confirmed, rows[("c-tar", "v1")]]) == {}


async def test_a_gone_record_on_an_unknown_component_is_applied_after_confirming(
    client, queued  # noqa: F811
):
    """CVE-2024-28863 on ViewPoint 7.2.0 (2026-11-23): the record of a finding
    that went before tracking has no component; the finding on the recreated
    component is unassessed. River proposes it; a person confirms and applies."""
    from contextlib import closing

    from dtvp.same_issue import REASON_UNKNOWN_COMPONENT

    queued.get_analysis.return_value = None
    old = {**_finding(1), "analysis": {"analysisState": "NOT_AFFECTED", "analysisDetails": "Not used."}}
    queued.get_vulnerabilities.return_value = [old]
    await main.cache_manager.get_vulnerabilities(queued, "p1", refresh=True)
    lifecycle = main.cache_manager.finding_lifecycle
    # As a row made for a record from before tracking: nothing is known of
    # its component.
    with closing(lifecycle._connect()) as connection, connection:
        connection.execute(
            "UPDATE finding_presence SET component_identity = NULL, component_purl = NULL,"
            " component_name = NULL, component_version = NULL, predates_tracking = 1"
            " WHERE component_uuid = 'component-1'"
        )
    lifecycle._presence.pop("p1", None)
    recreated = {**_finding(1), "component": {**_finding(1)["component"], "uuid": "component-9"},
                 "analysis": {}}
    queued.get_vulnerabilities.return_value = [recreated]
    await main.cache_manager.get_vulnerabilities(queued, "p1", refresh=True)
    assert main.cache_manager.get_assessment_overlay("p1", "component-9", "vuln-1") is None

    [finding] = [
        item for item in client.get("/api/project/p1/gone-findings").json()["findings"]
        if item["component_uuid"] == "component-1"
    ]
    guess = finding["same_issue"]
    assert (guess["component_uuid"], guess["reason"], guess["proposal"]) == (
        "component-9", REASON_UNKNOWN_COMPONENT, "copy"
    )
    assert (guess["component_name"], guess["component_version"]) == ("library-a", "2.0")

    request = {"project_uuid": "p1", "component_uuid": "component-1", "vulnerability_uuid": "vuln-1"}
    apply = {**request, "alias_vulnerability_uuid": "vuln-1", "alias_component_uuid": "component-9"}
    assert client.post("/api/gone-findings/apply-to-alias", json=apply).status_code == 409
    confirmed = client.post("/api/gone-findings/same-issue", json={
        **request, "other_component_uuid": "component-9", "other_vulnerability_uuid": "vuln-1",
    })
    assert confirmed.status_code == 200, confirmed.text
    applied = client.post("/api/gone-findings/apply-to-alias", json=apply)
    assert applied.status_code == 200, applied.text
    record = main.cache_manager.get_assessment_overlay("p1", "component-9", "vuln-1")
    assert record["analysisState"] == "NOT_AFFECTED"
    assert record["analysisDetails"].rstrip().endswith("[Status: Pending Review]")


async def test_every_candidate_of_an_unknown_component_is_listed(client, queued):  # noqa: F811
    """The vulnerability is reported on two components of the version: the
    gone finding lists both and picks none."""
    from contextlib import closing

    queued.get_analysis.return_value = None
    old = {**_finding(1), "analysis": {"analysisState": "NOT_AFFECTED", "analysisDetails": "Not used."}}
    queued.get_vulnerabilities.return_value = [old]
    await main.cache_manager.get_vulnerabilities(queued, "p1", refresh=True)
    lifecycle = main.cache_manager.finding_lifecycle
    with closing(lifecycle._connect()) as connection, connection:
        connection.execute(
            "UPDATE finding_presence SET component_identity = NULL, component_purl = NULL,"
            " component_name = NULL, component_version = NULL, predates_tracking = 1"
            " WHERE component_uuid = 'component-1'"
        )
    lifecycle._presence.pop("p1", None)

    def on(uuid, version):
        item = _finding(1)
        return {**item, "uuid": f"finding-{uuid}", "analysis": {},
                "component": {"name": "library-a", "uuid": uuid, "version": version}}

    queued.get_vulnerabilities.return_value = [on("component-8", "1.0"), on("component-9", "2.0")]
    await main.cache_manager.get_vulnerabilities(queued, "p1", refresh=True)

    [finding] = [
        item for item in client.get("/api/project/p1/gone-findings").json()["findings"]
        if item["component_uuid"] == "component-1"
    ]
    guess = finding["same_issue"]
    assert guess["ambiguous"] is True
    assert [(c["component_uuid"], c["component_version"], c["proposal"]) for c in guess["candidates"]] == [
        ("component-8", "1.0", "copy"), ("component-9", "2.0", "copy"),
    ]


async def test_earlier_assessments_list_what_gone_findings_of_the_vulnerability_hold(
    client, queued  # noqa: F811
):
    """A finding without an assessment: the form offers what River still holds
    for gone findings of the same vulnerability in the version, and of its
    aliases; nothing is applied."""
    from contextlib import closing

    queued.get_analysis.return_value = None
    text = (
        "[Response: WILL_NOT_FIX]\n\n"
        "--- [Team: General] [State: NOT_AFFECTED] [Assessed By: rita] "
        "[Justification: CODE_NOT_REACHABLE] ---\n"
        "tar functionality is not used in the product."
    )
    queued.get_vulnerabilities.return_value = [_finding(1)]
    await main.cache_manager.get_vulnerabilities(queued, "p1", refresh=True)
    await main.cache_manager.persist_assessment_updates([{
        "project_uuid": "p1", "component_uuid": "component-1", "vulnerability_uuid": "vuln-1",
        "state": "NOT_AFFECTED", "details": text, "suppressed": False,
    }], author="rita")
    lifecycle = main.cache_manager.finding_lifecycle
    with closing(lifecycle._connect()) as connection, connection:
        connection.execute(
            "UPDATE finding_presence SET component_identity = NULL, component_purl = NULL,"
            " component_name = NULL, component_version = NULL, predates_tracking = 1"
            " WHERE component_uuid = 'component-1'"
        )
    lifecycle._presence.pop("p1", None)
    new = {**_finding(1), "component": {**_finding(1)["component"], "uuid": "component-9"}, "analysis": {}}
    queued.get_vulnerabilities.return_value = [new]
    await main.cache_manager.get_vulnerabilities(queued, "p1", refresh=True)

    response = client.get("/api/project/p1/earlier-assessments", params={"vulnerability_uuid": "vuln-1"})
    assert response.status_code == 200, response.text
    [entry] = response.json()["earlier"]
    assert (entry["component_uuid"], entry["component_name"], entry["state"], entry["justification"],
            entry["response"], entry["alias"]) == (
        "component-1", None, "NOT_AFFECTED", "CODE_NOT_REACHABLE", "WILL_NOT_FIX", False,
    )
    assert entry["preview"] == "tar functionality is not used in the product."
    assert entry["teams"][0]["team"] == "General"
    # Nothing was written.
    assert main.cache_manager.get_assessment_overlay("p1", "component-9", "vuln-1") is None
    # Only the vulnerability asked for: CVE-2026-0002 went too, with its own.
    other = client.get("/api/project/p1/earlier-assessments", params={"vulnerability_uuid": "vuln-2"})
    assert [item["vuln_id"] for item in other.json()["earlier"]] == ["CVE-2026-0002"]
    nothing = client.get("/api/project/p1/earlier-assessments", params={"vulnerability_uuid": "vuln-x"})
    assert nothing.json()["earlier"] == []
