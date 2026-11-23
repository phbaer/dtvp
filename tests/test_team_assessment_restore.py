"""Restoring team assessments from a Dependency-Track export (synthetic data)."""

import asyncio
import copy
import dataclasses
import json
from datetime import UTC, datetime
from unittest.mock import patch

import pytest

from dtvp import main
from dtvp.assessment_model import canonical_assessment_text, parse_assessment
from dtvp.bulk_workflows.base import BulkWorkflowContext
from dtvp.bulk_workflows.team_assessment_restore import (
    REVIEW_LOOSE_MATCH,
    REVIEW_NO_ASSESSMENT,
    REVIEW_WORSE_STATE,
    build_team_assessment_restore_payloads,
    build_team_assessment_restore_preview,
    create_team_assessment_restore_workflow,
)
from dtvp.cyclonedx_export import build_vdr
from dtvp.grouped_vuln_services import summarize_grouped_vulnerabilities
from dtvp.logic import calculate_aggregated_state, parse_assessment_blocks
from dtvp.team_assessment_restore_services import (
    DTVP_EXPORT_MESSAGE,
    RestoreSourceError,
    RestoreSourceStore,
    append_blocks,
    match_entries,
    missing_blocks,
    read_dependency_track_vdr,
    restored_block,
)
from tests.test_cyclonedx_export import SCHEMA_BOM, _finding, _schema_errors

PROJECT = "proj-1"
DAY1 = 1893456000000  # 2030-01-01
DAY2 = 1893542400000  # 2030-01-02


def _block(team, state="NOT_AFFECTED", text="Not reachable.", **tags):
    header = [f"[Team: {team}]", f"[State: {state}]"]
    for name, value in tags.items():
        header.append(f"[{name.replace('_', ' ')}: {value}]")
    return f"--- {' '.join(header)} ---\n{text}"


def _vuln(vid, ref, affects, detail, state="not_affected"):
    return {
        "bom-ref": ref,
        "id": vid,
        "analysis": {"state": state, "detail": detail},
        "affects": [{"ref": item} for item in affects],
    }


COMPONENTS = [
    {"type": "library", "bom-ref": "c-1", "name": "lib-a", "version": "1.0",
     "purl": "pkg:npm/lib-a@1.0"},
    {"type": "library", "bom-ref": "c-2", "group": "org.example", "name": "lib-b",
     "version": "2.0"},
    {"type": "library", "bom-ref": "c-3", "name": "lib-c", "version": "3.0",
     "purl": "pkg:npm/lib-c@3.0",
     "components": [{"type": "library", "bom-ref": "c-4", "name": "lib-d",
                     "version": "4.0", "purl": "pkg:npm/lib-d@4.0"}]},
]


def _dt_export(vulnerabilities, *, spec="1.5", tools=None, project=None, **extra):
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": spec,
        "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000001",
        "version": 1,
        "metadata": {
            "timestamp": "2030-01-03T00:00:00Z",
            "tools": tools if tools is not None else [
                {"vendor": "OWASP", "name": "Dependency-Track", "version": "4.99.0"}
            ],
            "component": project or {
                "type": "application", "bom-ref": PROJECT, "name": "App", "version": "1.0"
            },
        },
        "components": COMPONENTS,
        "vulnerabilities": vulnerabilities,
        **extra,
    }
    return json.dumps(document).encode()


def _instance(component_uuid, vuln_uuid, *, details="", state="NOT_SET", project=PROJECT,
              name="lib-a", version="1.0", purl="pkg:npm/lib-a@1.0", group=None,
              project_name="App", project_version="1.0", **extra):
    return {
        "project_uuid": project,
        "project_name": project_name,
        "project_version": project_version,
        "component_uuid": component_uuid,
        "component_name": name,
        "component_version": version,
        "component_group": group,
        "component_purl": purl,
        "vulnerability_uuid": vuln_uuid,
        "analysis_state": state,
        "analysis_details": details,
        "justification": extra.pop("justification", "NOT_SET"),
        "is_suppressed": extra.pop("is_suppressed", False),
        **extra,
    }


def _group(gid, *instances, aliases=()):
    return {
        "id": gid,
        "title": f"Title of {gid}",
        "severity": "HIGH",
        "aliases": list(aliases),
        "tags": [],
        "affected_versions": [
            {"project_uuid": instances[0]["project_uuid"], "project_name": "App",
             "project_version": "1.0", "components": list(instances)}
        ],
    }


def _context(source, groups, team_mapping=None):
    return BulkWorkflowContext(
        task_id="task-1", groups=groups, user="rita",
        team_mapping=team_mapping or {}, source=source,
    )


# -- reading the export -------------------------------------------------------


def test_a_1_5_export_with_the_legacy_tools_array_is_read():
    detail = "\n\n".join([
        _block("TeamA", Assessed_By="alice", Date=DAY1, Ticket="ABC-1"),
        _block("TeamB", "EXPLOITABLE", "Reachable.", Assessed_By="bob"),
    ])
    content = _dt_export([_vuln("CVE-2099-0001", "v-1", ["c-1"], detail)])
    source = read_dependency_track_vdr(content)

    assert (source.tool, source.tool_version, source.spec_version) == (
        "Dependency-Track", "4.99.0", "1.5",
    )
    assert (source.project_uuid, source.project_name, source.project_version) == (
        PROJECT, "App", "1.0",
    )
    assert source.timestamp == "2030-01-03T00:00:00Z"
    assert len(source.sha256) == 64 and source.warnings == ()
    [entry] = source.entries
    assert (entry.vuln_id, entry.vuln_ref, entry.component_ref) == ("CVE-2099-0001", "v-1", "c-1")
    assert entry.component == {"purl": "pkg:npm/lib-a@1.0", "group": "", "name": "lib-a", "version": "1.0"}
    assert entry.analysis_state == "not_affected"
    assert [(b["team"], b["state"], b["assessed_by"], b["ticket"]) for b in entry.blocks] == [
        ("TeamA", "NOT_AFFECTED", "alice", "ABC-1"),
        ("TeamB", "EXPLOITABLE", "bob", None),
    ]
    assert source.analyses == 1 and source.team_blocks == 2


def test_a_1_6_export_with_tool_components_and_several_affects_is_read():
    content = _dt_export(
        [_vuln("CVE-2099-0002", "v-2", ["c-2", "c-4", "c-unknown"], _block("TeamA"))],
        spec="1.6",
        tools={"components": [{"type": "application", "name": "Dependency-Track", "version": "5.0.0"}]},
    )
    source = read_dependency_track_vdr(content)
    assert source.tool_version == "5.0.0"
    assert [entry.component_ref for entry in source.entries] == ["c-2", "c-4", "c-unknown"]
    # Nested components are found; an unknown reference has no component.
    assert source.entries[0].component["group"] == "org.example"
    assert source.entries[1].component["purl"] == "pkg:npm/lib-d@4.0"
    assert source.entries[2].component == {"purl": "", "group": "", "name": "", "version": ""}


def test_another_tool_is_a_warning_not_a_rejection():
    content = _dt_export([], tools=[{"name": "Other", "version": "1"}])
    source = read_dependency_track_vdr(content)
    assert source.tool == "Other" and len(source.warnings) == 1


@pytest.mark.parametrize("content, message", [
    (b"not json", "not JSON"),
    (b"[1, 2]", "not a CycloneDX"),
    (json.dumps({"bomFormat": "SPDX"}).encode(), "not a CycloneDX"),
    (json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5"}).encode(), "no vulnerabilities"),
    (json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.2", "vulnerabilities": []}).encode(),
     "not supported"),
])
def test_what_is_not_a_dependency_track_export_is_rejected(content, message):
    with pytest.raises(RestoreSourceError, match=message):
        read_dependency_track_vdr(content)


def test_dtvp_s_own_export_is_rejected():
    document = build_vdr(
        SCHEMA_BOM,
        [_finding({"uuid": "c1", "name": "lib-a", "version": "1.0"}, "CVE-2099-0003")],
        [parse_assessment("NOT_AFFECTED", _block("TeamA"), False)],
        generated_at=datetime(2030, 1, 1, tzinfo=UTC),
    )
    with pytest.raises(RestoreSourceError) as raised:
        read_dependency_track_vdr(json.dumps(document).encode())
    assert str(raised.value) == DTVP_EXPORT_MESSAGE


def test_analyses_without_team_blocks_are_counted():
    content = _dt_export([
        _vuln("CVE-2099-0004", "v-4", ["c-1"], "Plain text only."),
        _vuln("CVE-2099-0005", "v-5", ["c-1"], ""),
        _vuln("CVE-2099-0006", "v-6", ["c-1"], _block("TeamA")),
    ])
    source = read_dependency_track_vdr(content)
    assert source.analyses == 2
    assert source.no_team_blocks == 1
    assert [bool(entry.blocks) for entry in source.entries] == [False, True]


def test_a_repeated_team_keeps_its_newest_block():
    detail = "\n\n".join([
        _block("TeamA", "EXPLOITABLE", "Old.", Date=DAY1),
        _block("teama", "NOT_AFFECTED", "New.", Date=DAY2),
        _block("TeamB", text="Short.", Date=DAY1),
        _block("TeamB", text="The longer text.", Date=DAY1),
    ])
    [entry] = read_dependency_track_vdr(_dt_export([_vuln("CVE-2099-0007", "v-7", ["c-1"], detail)])).entries
    assert [(b["team"], b["details"]) for b in entry.blocks] == [
        ("teama", "New."), ("TeamB", "The longer text."),
    ]


# -- matching -----------------------------------------------------------------


def _source(*vulns, **options):
    return read_dependency_track_vdr(_dt_export(list(vulns), **options))


def test_an_entry_matches_its_finding_by_uuid():
    finding = _instance("c-1", "v-1")
    matches, unmatched = match_entries(
        _source(_vuln("CVE-2099-0001", "v-1", ["c-1"], _block("TeamA"))),
        [_group("CVE-2099-0001", finding)],
    )
    assert [(m.instance is finding, m.match) for m in matches] == [(True, "uuid")]
    assert unmatched == []


def test_a_recreated_component_matches_by_purl():
    finding = _instance("c-new", "v-1")
    [match], _ = match_entries(
        _source(_vuln("CVE-2099-0001", "v-1", ["c-1"], _block("TeamA"))),
        [_group("CVE-2099-0001", finding)],
    )
    assert match.match == "purl"


def test_a_component_without_purl_matches_by_group_name_and_version():
    finding = _instance("c-new", "v-1", name="lib-b", version="2.0", purl=None, group="org.example")
    [match], _ = match_entries(
        _source(_vuln("CVE-2099-0001", "v-other", ["c-2"], _block("TeamA"))),
        [_group("CVE-2099-0001", finding)],
    )
    assert match.match == "name_version"


def test_an_alias_of_the_vulnerability_matches():
    finding = _instance("c-new", "v-new")
    [match], _ = match_entries(
        _source(_vuln("GHSA-0000-0000-0001", "v-1", ["c-1"], _block("TeamA"))),
        [_group("CVE-2099-0001", finding, aliases=["GHSA-0000-0000-0001"])],
    )
    assert match.instance is finding and match.match == "purl"


def test_two_candidates_are_ambiguous_and_nothing_is_guessed():
    first = _instance("c-x", "v-x")
    second = _instance("c-y", "v-y")
    matches, [unmatched] = match_entries(
        _source(_vuln("CVE-2099-0001", "v-1", ["c-1"], _block("TeamA"))),
        [_group("CVE-2099-0001", first, second)],
    )
    assert matches == []
    assert (unmatched.reason, unmatched.candidates) == ("ambiguous", 2)


def test_an_export_of_another_project_matches_nothing():
    finding = _instance("c-1", "v-1", project="proj-2", project_name="Other")
    matches, [unmatched] = match_entries(
        _source(_vuln("CVE-2099-0001", "v-1", ["c-1"], _block("TeamA"))),
        [_group("CVE-2099-0001", finding)],
    )
    assert matches == [] and unmatched.reason == "other_project"


def test_a_recreated_project_matches_by_name_and_version():
    finding = _instance("c-new", "v-new", project="proj-recreated")
    [match], _ = match_entries(
        _source(_vuln("CVE-2099-0001", "v-1", ["c-1"], _block("TeamA"))),
        [_group("CVE-2099-0001", finding)],
    )
    assert match.match == "project_name_version"


def test_two_entries_on_one_finding_keep_the_exact_match():
    finding = _instance("c-1", "v-1")
    source = _source(
        _vuln("CVE-2099-0001", "v-1", ["c-1"], _block("TeamA")),
        # Another component with the same package URL in the export.
        _vuln("CVE-2099-0001", "v-1b", ["c-1"], _block("TeamB")),
    )
    matches, unmatched = match_entries(source, [_group("CVE-2099-0001", finding)])
    assert [m.entry.vuln_ref for m in matches] == ["v-1"]
    assert [(u.entry.vuln_ref, u.reason) for u in unmatched] == [("v-1b", "ambiguous")]

    # Without an exact match, neither entry decides.
    moved = _instance("c-new", "v-new")
    matches, unmatched = match_entries(source, [_group("CVE-2099-0001", moved)])
    assert matches == [] and {u.reason for u in unmatched} == {"ambiguous"}


def test_an_entry_without_a_finding_in_view_is_unmatched():
    matches, [unmatched] = match_entries(
        _source(_vuln("CVE-2099-0009", "v-9", ["c-3"], _block("TeamA"))),
        [_group("CVE-2099-0001", _instance("c-1", "v-1"))],
    )
    assert unmatched.reason == "no_finding_in_view"


# -- what a finding lacks ------------------------------------------------------


def _fields(team, state="NOT_AFFECTED", text="Not reachable.", **tags):
    [block] = parse_assessment_blocks(_block(team, state, text, **tags))[1]
    from dtvp.assessment_model import team_from_block

    return team_from_block(block)


def test_a_live_block_of_the_team_or_an_alias_is_present():
    mapping = {"comp": ["TeamA", "Team-A-Alias"]}
    current = _block("Team-A-Alias", "NOT_AFFECTED")
    restore, report = missing_blocks(current, [_fields("TeamA")], mapping)
    assert restore == [] and report["present"] == 1
    # Case alone is enough without a mapping.
    restore, report = missing_blocks(_block("teama"), [_fields("TeamA")], {})
    assert restore == [] and report["present"] == 1


def test_a_historical_block_is_present():
    current = _block("TeamA", "EXPLOITABLE", Historical="yes")
    restore, _ = missing_blocks(current, [_fields("TeamA")], {})
    assert restore == []


def test_a_former_team_note_naming_the_team_is_present():
    current = _block(
        "General", "NOT_AFFECTED",
        "Former team assessment (TeamC, TeamA, NOT_AFFECTED; assessed by alice | "
        "TeamD, EXPLOITABLE; ticket ABC-1):\nOld text.",
    )
    restore, report = missing_blocks(
        current, [_fields("TeamA"), _fields("TeamD"), _fields("TeamE")], {}
    )
    assert [block["team"] for block in restore] == ["TeamE"]
    assert report["present"] == 2


def test_an_absent_team_is_restored_with_every_tag():
    source = _fields(
        "TeamB", "EXPLOITABLE", "Reachable through the API.",
        Assessed_By="bob", Reviewed_By="rita", Date=DAY1,
        Justification="NOT_SET", Ticket="ABC-1, ABC-2", Rescored="8.1",
        Rescored_Vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        SSVC="IMMEDIATE", Evidence_Reviewed="yes", Version_Coverage="1.0",
        Assigned="carol, dave", Copied_From="TeamZ",
    )
    [restore], _ = missing_blocks(_block("TeamA"), [source], {})
    block = restored_block(restore)
    assert block["historical"] is True and block["assigned"] == []
    for key in ("team", "state", "assessed_by", "reviewed_by", "assessed_at_ms", "ticket",
                "rescored_score", "rescored_vector", "ssvc", "evidence_reviewed",
                "version_coverage", "copied_from", "details"):
        assert block[key] == source[key], key
    assert source["assigned"] == ["carol", "dave"]

    text = append_blocks(_block("TeamA"), [block])
    [_, restored] = parse_assessment("NOT_AFFECTED", text, False)["teams"]
    assert restored == {**block, "justification": None}
    assert "Assigned" not in text


def test_an_undated_block_stays_undated_and_unknown_is_no_assessor():
    block = restored_block(_fields("TeamB", Assessed_By="unknown"))
    assert block["assessed_at_ms"] is None and block["assessed_by"] is None
    text = append_blocks("", [block])
    assert "[Date:" not in text
    [team] = parse_assessment("NOT_SET", text, False)["teams"]
    assert team["assessed_at_ms"] is None and team["assessed_by"] is None


def test_empty_and_reference_blocks_are_not_restored():
    empty = _fields("TeamB", "NOT_SET", "")
    reference = _fields("TeamC", "NOT_AFFECTED", "See global assessment.")
    with_ticket = _fields("TeamD", "NOT_AFFECTED", "See global assessment.", Ticket="ABC-1")
    restore, report = missing_blocks("", [empty, reference, with_ticket], {})
    assert [block["team"] for block in restore] == ["TeamD"]
    assert (report["empty"], report["reference"]) == (1, 1)


def test_a_reference_or_empty_placeholder_does_not_make_a_team_present():
    lost = _fields(
        "TeamX", "NOT_AFFECTED", "Component not shipped.",
        Assessed_By="alice", Date="1735689600000",
        Justification="CODE_NOT_PRESENT", Ticket="X-7",
    )
    general = _block("General", "NOT_AFFECTED", "Approved.")
    for current in (
        f"{general}\n\n{_block('TeamX', 'NOT_AFFECTED', 'See global assessment.')}",
        "--- [Team: TeamX] [State: NOT_SET] [Assigned: bob] ---",
    ):
        restore, report = missing_blocks(current, [lost], {})
        assert [block["ticket"] for block in restore] == ["X-7"]
        assert report["present"] == 0 and report["notes"] == []
    # A historical record of the team or a block with a text still counts.
    for current in (
        _block("TeamX", "NOT_AFFECTED", "See global assessment.", Historical="yes"),
        _block("TeamX", "NOT_SET", "Looking into it."),
    ):
        assert missing_blocks(current, [lost], {})[0] == []


def test_the_general_assessment_is_not_restored():
    restore, report = missing_blocks("", [_fields("General", "EXPLOITABLE")], {})
    assert restore == [] and report["general"] == 1


def test_missing_tickets_and_copies_are_reported_but_not_written():
    current = "\n\n".join([
        _block("TeamA", Ticket="ABC-12"),
        _block("TeamC", Copied_From="TeamB"),
    ])
    restore, report = missing_blocks(
        current, [_fields("TeamA", Ticket="ABC-1"), _fields("TeamB")], {}
    )
    assert [block["team"] for block in restore] == ["TeamB"]
    assert report["notes"] == [
        {"kind": "present_ticket_missing", "team": "TeamA", "tickets": ["ABC-1"]},
        {"kind": "copied_from", "team": "TeamB", "copied_to": "TeamC"},
    ]


# -- payloads -----------------------------------------------------------------


PREAMBLE = (
    "[Rescored: 2.5] [Rescored Vector: CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N] "
    "[Response: WILL_NOT_FIX]\n\nShared remark."
)
SSVC_RECORD = '[SSVC Details]\n{"outcome": "DEFER"}\n[/SSVC Details]'


def _assessed_finding():
    details = (
        f"{PREAMBLE}\n\n"
        "--- [Team: General] [State: NOT_AFFECTED] [Assessed By: alice] "
        "[Justification: CODE_NOT_REACHABLE] ---\nNot reachable.\n\n"
        f"{SSVC_RECORD}\n\n"
        f"{_block('TeamA', Assessed_By='alice', Date=DAY1)}\n\n"
        "[Status: Pending Review]"
    )
    return _instance(
        "c-1", "v-1", details=details, state="NOT_AFFECTED",
        justification="CODE_NOT_REACHABLE", is_suppressed=True,
    )


def _export_with(*blocks):
    return _source(_vuln("CVE-2099-0001", "v-1", ["c-1"], "\n\n".join(blocks)))


def test_a_payload_changes_nothing_but_the_added_blocks():
    finding = _assessed_finding()
    before = finding["analysis_details"]
    context = _context(
        _export_with(
            _block("TeamA"),
            _block("TeamB", "EXPLOITABLE", "Reachable.", Assessed_By="bob", Date=DAY2, Ticket="ABC-1"),
            _block("TeamC", "NOT_AFFECTED", "Not shipped.", Date=DAY1),
            _block("TeamD", "FALSE_POSITIVE", "Wrong match."),
        ),
        [_group("CVE-2099-0001", finding)],
    )
    preview = build_team_assessment_restore_preview(context)
    [item] = preview["items"]
    assert (item["finding_count"], item["restore_count"]) == (1, 3)
    assert item["requires_review"] and REVIEW_WORSE_STATE in item["review"]
    assert [(b["team"], b["date"]) for b in item["blocks"]] == [
        ("TeamB", "2030-01-02"), ("TeamC", "2030-01-01"), ("TeamD", None),
    ]
    assert preview["summary"]["blocks_to_restore"] == 3
    assert preview["summary"]["skipped"]["present"] == 1

    [(instance, payload)], skipped = build_team_assessment_restore_payloads(context, ["CVE-2099-0001"])
    assert instance is finding
    assert skipped == {
        "missing_identity": 0, "unchanged": 0, "unreadable": 0, "state_would_change": 0,
        "changed_since_preview": 0,
    }
    assert (payload["state"], payload["justification"], payload["suppressed"]) == (
        "NOT_AFFECTED", "CODE_NOT_REACHABLE", True,
    )
    details = payload["details"]
    assert calculate_aggregated_state(details) == calculate_aggregated_state(before) == "NOT_AFFECTED"
    # Everything that was there stays, byte for byte; the marker stays last.
    head = before[: before.index("[Status: Pending Review]")].rstrip()
    assert details.startswith(head)
    assert details.endswith("\n\n[Status: Pending Review]")
    assert SSVC_RECORD in details and details.startswith(PREAMBLE)
    # Oldest first, undated last.
    order = [details.index(f"[Team: {team}]") for team in ("TeamC", "TeamB", "TeamD")]
    assert order == sorted(order)

    stored = canonical_assessment_text("NOT_AFFECTED", details, True)
    fields = parse_assessment("NOT_AFFECTED", stored, True)
    assert fields["response"] == "WILL_NOT_FIX" and fields["pending_review"]
    assert fields["rescored_score"] == 2.5
    historical = {team["team"]: team for team in fields["teams"] if team["historical"]}
    assert set(historical) == {"TeamB", "TeamC", "TeamD"}
    assert historical["TeamB"]["ticket"] == "ABC-1"
    assert historical["TeamB"]["assessed_by"] == "bob"
    assert historical["TeamB"]["state"] == "EXPLOITABLE"


def test_an_exploitable_restore_on_a_not_affected_finding_needs_review_and_keeps_the_state():
    finding = _instance(
        "c-1", "v-1", state="NOT_AFFECTED", details=_block("TeamA", Assessed_By="alice"),
    )
    context = _context(
        _export_with(_block("TeamB", "EXPLOITABLE", "Reachable.")),
        [_group("CVE-2099-0001", finding)],
    )
    [item] = build_team_assessment_restore_preview(context)["items"]
    assert item["requires_review"] and item["status"] == "Review first"
    assert item["current_state"] == "NOT_AFFECTED"
    [(_, payload)], _ = build_team_assessment_restore_payloads(context, ["CVE-2099-0001"])
    assert payload["state"] == "NOT_AFFECTED"
    assert calculate_aggregated_state(payload["details"]) == "NOT_AFFECTED"


def test_a_finding_without_assessment_and_a_loose_match_need_review():
    unassessed = _instance("c-1", "v-1")
    context = _context(_export_with(_block("TeamA")), [_group("CVE-2099-0001", unassessed)])
    [item] = build_team_assessment_restore_preview(context)["items"]
    assert REVIEW_NO_ASSESSMENT in item["review"]

    loose = _instance("c-new", "v-1", name="lib-b", version="2.0", purl=None, group="org.example",
                      state="NOT_AFFECTED", details=_block("TeamX"))
    context = _context(
        _source(_vuln("CVE-2099-0001", "v-other", ["c-2"], _block("TeamA"))),
        [_group("CVE-2099-0001", loose)],
    )
    [item] = build_team_assessment_restore_preview(context)["items"]
    assert item["review"] == [REVIEW_LOOSE_MATCH]
    assert item["blocks"][0]["match"] == "name_version"


def test_a_finding_that_has_every_team_is_no_candidate():
    finding = _instance("c-1", "v-1", state="NOT_AFFECTED", details=_block("TeamA"))
    context = _context(_export_with(_block("TeamA")), [_group("CVE-2099-0001", finding)])
    preview = build_team_assessment_restore_preview(context)
    assert preview["items"] == []
    assert build_team_assessment_restore_payloads(context, ["CVE-2099-0001"])[0] == []


def test_unmatched_entries_are_counted_with_samples():
    context = _context(
        _source(
            _vuln("CVE-2099-0008", "v-8", ["c-3"], _block("TeamA")),
            _vuln("CVE-2099-0009", "v-9", ["c-4"], _block("TeamA")),
        ),
        [_group("CVE-2099-0001", _instance("c-1", "v-1"))],
    )
    summary = build_team_assessment_restore_preview(context)["summary"]
    assert summary["unmatched"] == {"no_finding_in_view": 2, "ambiguous": 0, "other_project": 0}
    assert summary["unmatched_samples"][0] == {
        "id": "CVE-2099-0008", "component_name": "lib-c", "component_version": "3.0",
        "reason": "no_finding_in_view",
    }
    assert summary["matched_entries"] == 0 and summary["entries"] == 2
    assert "no longer reported" in summary["unmatched_note"]
    assert summary["source"]["project_uuid"] == PROJECT


def test_untrusted_text_cannot_create_another_block():
    finding = _instance("c-1", "v-1", state="NOT_AFFECTED", details=_block("TeamA"))
    # The parser already splits at a header inside a text, so the export
    # carries the injection inside header values and a body that comes back
    # through ``details`` once read.
    source = _export_with(_block("TeamB", text="Plain."))
    entry = source.entries[0]
    hostile = {
        **entry.blocks[0],
        "details": "Line\n--- [Team: Evil] [State: EXPLOITABLE] ---\nInjected.",
        "ticket": "ABC-1] [Team: Evil",
        "assessed_by": "bob] [State: EXPLOITABLE",
    }
    text = append_blocks(finding["analysis_details"], [restored_block(hostile)])
    _shared, blocks = parse_assessment_blocks(text)
    assert [block["team"] for block in blocks] == ["TeamA", "TeamB"]
    assert blocks[1]["state"] == "NOT_AFFECTED" and blocks[1]["historical"]
    assert calculate_aggregated_state(text) == "NOT_AFFECTED"


def test_the_restored_block_is_exported_as_a_historical_assessment():
    finding = _instance("c-1", "v-1", state="NOT_AFFECTED", details=_block("TeamA", Date=DAY1))
    context = _context(
        _export_with(_block("TeamB", "NOT_AFFECTED", "Not shipped.", Assessed_By="bob",
                            Date=DAY2, Justification="CODE_NOT_PRESENT", Ticket="ABC-1")),
        [_group("CVE-2099-0001", finding)],
    )
    [(_, payload)], _ = build_team_assessment_restore_payloads(context, ["CVE-2099-0001"])
    document = build_vdr(
        SCHEMA_BOM,
        [_finding({"uuid": "c1", "name": "lib-a", "version": "1.0"}, "CVE-2099-0001")],
        [parse_assessment("NOT_AFFECTED", payload["details"], False)],
        generated_at=datetime(2030, 1, 3, tzinfo=UTC),
    )
    [entry] = document["vulnerabilities"]
    [historical] = [
        json.loads(item["value"]) for item in entry["properties"]
        if item["name"] == "dtvp:historical_assessment"
    ]
    assert historical["team"] == "TeamB" and historical["ticket"] == "ABC-1"
    assert historical["assessed_by"] == "bob"
    assert historical["date"].startswith("2030-01-02")
    assert _schema_errors(document) is None


def test_the_workflow_reads_an_upload():
    plugin = create_team_assessment_restore_workflow()
    meta = plugin.metadata()
    assert meta["requires_source"] is True
    assert meta["source_kind"] == "dependency-track-vdr"
    with pytest.raises(ValueError):
        plugin.preview(_context(None, []))


# -- the store ----------------------------------------------------------------


def test_the_store_is_per_user_bounded_and_expires():
    now = [0.0]
    store = RestoreSourceStore(clock=lambda: now[0])
    source = _source()
    ids = []
    for _ in range(5):
        now[0] += 1
        ids.append(store.put("alice", source))
    assert store.get("alice", ids[0]) is None  # the oldest went first
    assert store.get("alice", ids[4]) is source
    assert store.get("bob", ids[4]) is None
    assert ids[4] != source.sha256
    now[0] += 6 * 60 * 60 + 1
    assert store.get("alice", ids[4]) is None


# -- routes -------------------------------------------------------------------


@pytest.fixture
def reviewer():
    main.app.dependency_overrides[main.get_current_user] = lambda: "rita"
    with patch("dtvp.main.get_user_role", return_value="REVIEWER"):
        yield
    main.app.dependency_overrides.pop(main.get_current_user, None)


def _task(groups, task_id="restore-source-task", owner="rita"):
    main.tasks[task_id] = {
        "_owner": owner,
        "status": "completed",
        "result_mode": "summary",
        "_full_result": groups,
        "_full_result_by_id": {group["id"]: group for group in groups},
        "result": summarize_grouped_vulnerabilities(groups, {}),
    }
    return task_id


def _upload(client, content):
    return client.post(
        "/api/bulk-workflows/sources",
        files={"file": ("export.json", content, "application/json")},
    )


def _route_export():
    return _dt_export([_vuln(
        "CVE-2099-0001", "v-1", ["c-1"],
        _block("TeamB", "NOT_AFFECTED", "Not shipped.", Assessed_By="bob", Date=DAY1, Ticket="ABC-1"),
    )])


def _route_group():
    return _group("CVE-2099-0001", _instance(
        "c-1", "v-1", state="NOT_AFFECTED",
        details=_block("TeamA", Assessed_By="alice", Date=DAY1),
        justification="CODE_NOT_REACHABLE",
    ))


def test_the_upload_is_for_reviewers_only(client):
    main.app.dependency_overrides[main.get_current_user] = lambda: "alice"
    try:
        with patch("dtvp.main.get_user_role", return_value="ANALYST"):
            response = _upload(client, _route_export())
    finally:
        main.app.dependency_overrides.pop(main.get_current_user, None)
    assert response.status_code == 403


def test_an_upload_above_the_limit_is_refused(client, reviewer, monkeypatch):
    from dtvp import team_assessment_restore_services

    monkeypatch.setattr(team_assessment_restore_services, "TEAM_RESTORE_MAX_UPLOAD_BYTES", 10)
    assert _upload(client, _route_export()).status_code == 413


def test_a_dtvp_export_upload_is_refused(client, reviewer):
    document = build_vdr(SCHEMA_BOM, [], [], generated_at=datetime(2030, 1, 1, tzinfo=UTC))
    response = _upload(client, json.dumps(document).encode())
    assert response.status_code == 422
    assert response.json()["detail"] == DTVP_EXPORT_MESSAGE


def _wait(client, operation_id):
    for _ in range(100):
        status = client.get(f"/api/bulk-workflows/tasks/{operation_id}").json()
        if status["status"] in {"completed", "failed"}:
            return status
    raise AssertionError("bulk workflow task did not finish")


def _store(*instances):
    """What DTVP has stored for the findings, as the task snapshot shows it."""
    for instance in instances:
        main.cache_manager._save_project_cache(
            main.cache_manager._findings_path(instance["project_uuid"]),
            [{
                "component": {"uuid": instance["component_uuid"]},
                "vulnerability": {"uuid": instance["vulnerability_uuid"]},
                "analysis": {
                    "analysisState": instance["analysis_state"],
                    "analysisDetails": instance["analysis_details"],
                    "isSuppressed": instance["is_suppressed"],
                },
            }],
        )


def test_preview_and_apply_with_an_uploaded_export(client, reviewer, mock_dt_client):
    group = _route_group()
    _store(group["affected_versions"][0]["components"][0])
    task_id = _task([group])
    upload = _upload(client, _route_export())
    assert upload.status_code == 200
    body = upload.json()
    assert body["entries"] == 1 and body["team_blocks"] == 1
    assert body["summary"]["tool"] == "Dependency-Track"
    source_id = body["source_id"]

    # Without the upload, or with an unknown one, nothing runs.
    missing = client.post(
        "/api/bulk-workflows/team-assessment-restore/preview-task",
        json={"task_id": task_id, "filters": {}},
    )
    assert missing.status_code == 409
    unknown = client.post(
        "/api/bulk-workflows/team-assessment-restore/preview-task",
        json={"task_id": task_id, "filters": {}, "source_id": "no-such-upload"},
    )
    assert unknown.status_code == 404

    started = client.post(
        "/api/bulk-workflows/team-assessment-restore/preview-task",
        json={"task_id": task_id, "filters": {}, "source_id": source_id},
    )
    assert started.status_code == 200
    preview = _wait(client, started.json()["task_id"])["result"]
    assert preview["selectable_group_ids"] == ["CVE-2099-0001"]
    assert preview["workflow"]["requires_source"] is True
    assert preview["summary"]["source"]["sha256"] == body["summary"]["sha256"]

    # A preview of one file cannot be applied with another.
    other = _upload(client, _dt_export([_vuln(
        "CVE-2099-0001", "v-1", ["c-1"], _block("TeamB", "NOT_AFFECTED", "Not shipped."),
    )], serialNumber="urn:uuid:00000000-0000-4000-8000-000000000002")).json()["source_id"]
    stale = client.post(
        "/api/bulk-workflows/team-assessment-restore/apply",
        json={"task_id": task_id, "filters": {}, "source_id": other,
              "group_ids": ["CVE-2099-0001"], "preview_token": preview["preview_token"],
                  "group_fingerprints": preview["group_fingerprints"]},
    )
    assert stale.status_code == 409 and "stale" in stale.json()["detail"]

    applied = client.post(
        "/api/bulk-workflows/team-assessment-restore/apply",
        json={"task_id": task_id, "filters": {}, "source_id": source_id,
              "group_ids": ["CVE-2099-0001"], "preview_token": preview["preview_token"],
                  "group_fingerprints": preview["group_fingerprints"]},
    )
    assert applied.status_code == 200, applied.text
    assert applied.json()["summary"]["attempted"] == 1
    mock_dt_client.update_analysis.assert_not_called()

    [pending] = main.cache_manager._load_pending_updates()
    assert pending["payload"]["state"] == "NOT_AFFECTED"
    assert "[Team: TeamB]" in pending["payload"]["details"]
    assert "[Historical: yes]" in pending["payload"]["details"]
    history = client.get(
        "/api/assessments/history",
        params={"project_uuid": PROJECT, "component_uuid": "c-1", "vulnerability_uuid": "v-1"},
    ).json()
    assert history[0]["origin"] == "bulk-workflow"
    assert history[0]["author"] == "rita"
    main.tasks.pop(task_id, None)


def test_another_users_upload_is_not_found(client, reviewer):
    task_id = _task([_route_group()])
    source_id = _upload(client, _route_export()).json()["source_id"]
    main.app.dependency_overrides[main.get_current_user] = lambda: "other-reviewer"
    _task([_route_group()], task_id="other-task", owner="other-reviewer")
    response = client.post(
        "/api/bulk-workflows/team-assessment-restore/preview",
        json={"task_id": "other-task", "filters": {}, "source_id": source_id},
    )
    assert response.status_code == 404
    assert response.json()["detail"] == "Uploaded export not found; upload it again"
    main.tasks.pop(task_id, None)
    main.tasks.pop("other-task", None)


def test_other_workflows_still_work_without_an_upload(client, reviewer):
    task_id = _task([_route_group()])
    summary = client.post("/api/bulk-workflows/summary", json={"task_id": task_id, "filters": {}})
    by_id = {item["id"]: item for item in summary.json()["workflows"]}
    assert by_id["team-assessment-restore"]["requires_source"] is True
    assert by_id["assessment-repair"]["requires_source"] is False
    response = client.post(
        "/api/bulk-workflows/assessment-repair/preview",
        json={"task_id": task_id, "filters": {}},
    )
    assert response.status_code == 200
    main.tasks.pop(task_id, None)


def test_the_group_is_left_unchanged_by_a_preview():
    group = _route_group()
    snapshot = copy.deepcopy(group)
    build_team_assessment_restore_preview(_context(
        read_dependency_track_vdr(_route_export()), [group],
    ))
    assert group == snapshot


# -- a restored block stays ---------------------------------------------------


def _restored_text():
    """An approved General decision, team TeamU live, and team TeamT restored."""
    current = "\n\n".join([
        "--- [Team: General] [State: NOT_AFFECTED] [Assessed By: rev] "
        "[Justification: CODE_NOT_PRESENT] ---\nApproved globally.",
        _block("TeamU", Assessed_By="ulla", Date=DAY1),
    ])
    old = _fields("TeamT", "EXPLOITABLE", "Restored old text.", Assessed_By="tom",
                  Date=1600000000000, Ticket="SYN-1", Evidence_Reviewed="yes")
    return append_blocks(current, [restored_block(old)])


def _teams(text):
    return [
        (block["team"], block["historical"], block["details"])
        for block in parse_assessment_blocks(text)[1]
    ]


def test_a_team_save_keeps_the_restored_block_of_that_team():
    from dtvp.logic import process_assessment_details

    text = _restored_text()
    saved, state = process_assessment_details(
        "New decision.", "tess", "ANALYST", team="TeamT", state="NOT_AFFECTED",
        existing_details=text,
    )
    assert ("TeamT", True, "Restored old text.") in _teams(saved)
    assert ("TeamT", False, "New decision.") in _teams(saved)
    blocks = {(b["team"], b["historical"]): b for b in parse_assessment_blocks(saved)[1]}
    # The old ticket and checks stay with the old assessment, not the new one.
    assert blocks[("TeamT", True)]["ticket"] == "SYN-1"
    assert blocks[("TeamT", True)]["user"] == "tom"
    assert blocks[("TeamT", False)]["ticket"] is None
    assert blocks[("TeamT", False)]["evidence_reviewed"] is None
    assert state == "NOT_AFFECTED"
    # The store reads both; nothing refuses the text.
    stored = parse_assessment("NOT_AFFECTED", canonical_assessment_text("NOT_AFFECTED", saved, False), False)
    assert [(t["team"], t["historical"]) for t in stored["teams"]] == [
        ("General", False), ("TeamU", False), ("TeamT", True), ("TeamT", False),
    ]
    # A second save of the team replaces its live block only.
    again, _ = process_assessment_details(
        "Newer decision.", "tess", "ANALYST", team="TeamT", state="NOT_AFFECTED",
        existing_details=saved,
    )
    assert [t for t in _teams(again) if t[0] == "TeamT"] == [
        ("TeamT", True, "Restored old text."), ("TeamT", False, "Newer decision."),
    ]


def test_deleting_a_team_assessment_keeps_its_restored_block():
    from dtvp.logic import remove_assessment_blocks

    text = _restored_text().replace("[Team: TeamU]", "[Team: TeamT]")
    remaining = remove_assessment_blocks(text, "TeamT")
    assert _teams(remaining) == [
        ("General", False, "Approved globally."), ("TeamT", True, "Restored old text."),
    ]


def test_a_restored_block_survives_repair_and_the_next_save():
    from dtvp.logic import process_assessment_details
    from tests.test_bulk_workflows import _repair, _repair_group

    text = _restored_text()
    group = _repair_group([("NOT_AFFECTED", text)], tags=["TeamT", "TeamU"])
    _preview, payloads, _ = _repair(group)
    [(_instance, payload)] = payloads
    repaired = payload["details"]
    # TeamT has a historical block, so the repair adds no reference block.
    assert ("TeamT", False, "See global assessment.") not in _teams(repaired)
    assert ("TeamT", True, "Restored old text.") in _teams(repaired)

    saved, _ = process_assessment_details(
        "Still not shipped.", "ulla", "ANALYST", team="TeamU", state="NOT_AFFECTED",
        existing_details=repaired,
    )
    assert ("TeamT", True, "Restored old text.") in _teams(saved)
    assert "[Ticket: SYN-1]" in saved
    assert "Restored old text." in canonical_assessment_text("NOT_AFFECTED", saved, False)
    # And a second restore has nothing to add.
    restore, report = missing_blocks(saved, [_fields("TeamT", "EXPLOITABLE", "Restored old text.")], {})
    assert restore == [] and report["present"] == 1


def test_a_former_team_note_naming_teams_with_brackets_commas_and_bars_is_present():
    # As the repair wrote such a note before it kept former blocks as
    # historical blocks.
    note = (
        "Former team assessment (Core (EU), Ops, Inc. | Edge; NOT_AFFECTED; "
        "assessed by bob):\nNot reachable."
    )
    current = (
        "--- [Team: General] [State: NOT_AFFECTED] [Assessed By: rev] ---\n" + note
    )
    restore, report = missing_blocks(
        current,
        [_fields("Core (EU)"), _fields("Ops, Inc. | Edge"), _fields("bob"), _fields("Delta")],
        {},
    )
    # An assessor's name is no team of the note.
    assert [block["team"] for block in restore] == ["bob", "Delta"]
    assert report["present"] == 2


def test_a_former_team_note_naming_an_alias_is_present():
    mapping = {"comp": ["Core (EU)", "Core Europe"]}
    current = (
        "--- [Team: General] [State: NOT_AFFECTED] [Assessed By: rev] ---\n"
        "Former team assessment (Core Europe; NOT_AFFECTED; assessed by bob):\nNot reachable."
    )
    restore, report = missing_blocks(current, [_fields("Core (EU)")], mapping)
    assert restore == [] and report["present"] == 1


# -- rescoring ----------------------------------------------------------------


VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def _grouped(details):
    from dtvp.logic import group_vulnerabilities

    finding = {
        "component": {"uuid": "c-1", "name": "lib-a", "version": "1.0"},
        "vulnerability": {"uuid": "v-1", "vulnId": "CVE-2099-0001", "severity": "LOW",
                          "cvssV3BaseScore": 3.1},
        "analysis": {"analysisState": "NOT_AFFECTED", "analysisDetails": details},
    }
    [group] = group_vulnerabilities([{
        "version": {"name": "App", "version": "1.0", "uuid": PROJECT},
        "vulnerabilities": [finding],
    }], include_dependency_paths=False)
    return group


def test_a_restored_block_does_not_rescore_the_finding():
    finding = _instance("c-1", "v-1", state="NOT_AFFECTED", details=_block("TeamA"))
    context = _context(
        _export_with(_block(
            "TeamB", "NOT_AFFECTED", f"Quoted from the advisory: {VECTOR}",
            Rescored="9.8", Rescored_Vector=VECTOR,
        )),
        [_group("CVE-2099-0001", finding)],
    )
    [(_, payload)], _ = build_team_assessment_restore_payloads(context, ["CVE-2099-0001"])
    details = payload["details"]
    assert "[Rescored: 9.8]" in details and "[Historical: yes]" in details

    before, after = _grouped(finding["analysis_details"]), _grouped(details)
    for key in ("rescored_cvss", "rescored_vector", "severity"):
        assert after[key] == before[key], key
    assert after["rescored_cvss"] is None and after["rescored_vector"] is None


def test_the_finding_s_own_rescoring_still_counts_beside_a_restored_block():
    from dtvp.logic import without_historical_blocks

    own = f"[Rescored: 2.5] [Rescored Vector: {VECTOR}]\n\n{_block('TeamA')}"
    restored = append_blocks(own, [restored_block(_fields("TeamB", Rescored="9.8"))])
    assert without_historical_blocks(restored).strip() == own
    assert _grouped(restored)["rescored_cvss"] == 2.5


# -- notes and skip paths -----------------------------------------------------


def test_a_vulnerability_with_notes_only_is_shown_and_not_selectable():
    finding = _instance("c-1", "v-1", state="NOT_AFFECTED", details=_block("TeamA"))
    context = _context(
        _export_with(_block("TeamA", Ticket="ABC-1")),
        [_group("CVE-2099-0001", finding)],
    )
    preview = build_team_assessment_restore_preview(context)
    [item] = preview["items"]
    assert item["status"] == "Notes only" and item["restore_count"] == 0
    assert item["notes"] == [{
        "kind": "present_ticket_missing", "team": "TeamA", "tickets": ["ABC-1"],
        "component_name": "lib-a", "project_version": "1.0",
    }]
    assert preview["summary"]["groups"] == 0
    assert preview["summary"]["notes_only_groups"] == 1
    assert preview["summary"]["notes"] == 1
    assert create_team_assessment_restore_workflow().selectable_ids(preview) == []
    assert build_team_assessment_restore_payloads(context, ["CVE-2099-0001"])[0] == []


def _restore_context():
    finding = _instance("c-1", "v-1", state="NOT_AFFECTED", details=_block("TeamA"))
    context = _context(
        _export_with(_block("TeamB", "NOT_AFFECTED", "Not shipped.")),
        [_group("CVE-2099-0001", finding)],
    )
    return finding, context


def test_a_restore_that_would_change_the_state_is_skipped(monkeypatch):
    from dtvp.bulk_workflows import team_assessment_restore

    finding, context = _restore_context()
    states = iter(["NOT_AFFECTED", "EXPLOITABLE"] * 4)
    monkeypatch.setattr(
        team_assessment_restore, "calculate_aggregated_state", lambda _details: next(states),
    )
    preview = build_team_assessment_restore_preview(context)
    assert preview["items"] == []
    assert preview["summary"]["skipped"]["state_would_change"] == 1
    payloads, skipped = build_team_assessment_restore_payloads(context, ["CVE-2099-0001"])
    assert payloads == [] and skipped["state_would_change"] == 1


def test_a_restore_onto_an_unreadable_text_is_skipped(monkeypatch):
    from dtvp.bulk_workflows import team_assessment_restore

    def unreadable(*_args):
        raise ValueError("unreadable")

    _finding, context = _restore_context()
    monkeypatch.setattr(team_assessment_restore, "canonical_assessment_text", unreadable)
    preview = build_team_assessment_restore_preview(context)
    assert preview["items"] == []
    assert preview["summary"]["skipped"]["unreadable"] == 1
    payloads, skipped = build_team_assessment_restore_payloads(context, ["CVE-2099-0001"])
    assert payloads == [] and skipped["unreadable"] == 1


# -- saves after the preview --------------------------------------------------


def test_a_finding_saved_after_the_preview_is_left_out():
    finding, context = _restore_context()
    stored = {"state": "NOT_AFFECTED", "details": finding["analysis_details"],
              "suppressed": False, "revision": 3}
    context = dataclasses.replace(
        context, stored_assessments=lambda instances: [dict(stored) for _ in instances],
    )
    [(_, payload)], skipped = build_team_assessment_restore_payloads(context, ["CVE-2099-0001"])
    assert payload["expected_revision"] == 3 and skipped["changed_since_preview"] == 0

    stored["details"] += "\n\n" + _block("TeamC", "EXPLOITABLE", "Saved meanwhile.")
    payloads, skipped = build_team_assessment_restore_payloads(context, ["CVE-2099-0001"])
    assert payloads == [] and skipped["changed_since_preview"] == 1


def test_a_save_between_preview_and_write_is_not_overwritten(client, reviewer, mock_dt_client):
    """The apply loads the finding, a save lands, then the write: the save stays."""
    from dtvp.bulk_workflows import team_assessment_restore

    group = _route_group()
    instance = group["affected_versions"][0]["components"][0]
    _store(instance)
    task_id = _task([group])
    source_id = _upload(client, _route_export()).json()["source_id"]
    started = client.post(
        "/api/bulk-workflows/team-assessment-restore/preview-task",
        json={"task_id": task_id, "filters": {}, "source_id": source_id},
    )
    preview = _wait(client, started.json()["task_id"])["result"]

    later = instance["analysis_details"] + "\n\n" + _block("TeamC", text="Saved meanwhile.")
    original = team_assessment_restore.guard_against_later_saves

    def save_in_between(context, payloads, skipped):
        guarded = original(context, payloads, skipped)
        asyncio.run(main.cache_manager.persist_assessment_updates([{
            "project_uuid": PROJECT, "component_uuid": "c-1", "vulnerability_uuid": "v-1",
            "state": "NOT_AFFECTED", "details": later, "suppressed": False,
        }], replace=True, origin="user", author="carol"))
        return guarded

    with patch.object(team_assessment_restore, "guard_against_later_saves", save_in_between):
        applied = client.post(
            "/api/bulk-workflows/team-assessment-restore/apply",
            json={"task_id": task_id, "filters": {}, "source_id": source_id,
                  "group_ids": ["CVE-2099-0001"], "preview_token": preview["preview_token"],
                  "group_fingerprints": preview["group_fingerprints"]},
        )
    assert applied.status_code == 200, applied.text
    summary = applied.json()["summary"]
    assert summary["changed_since_preview"] == 1 and summary["queued"] == 0
    [stored] = main.cache_manager.get_cached_assessments([instance])
    assert "Saved meanwhile." in stored["details"]
    assert "[Team: TeamB]" not in stored["details"]
    main.tasks.pop(task_id, None)


def test_a_save_during_a_repair_apply_is_not_overwritten(client, reviewer, mock_dt_client):
    """Every workflow's payloads carry the revision they are based on, not
    only the restore's: a save that lands while a repair applies stays."""
    from dtvp.bulk_workflows import base

    general = _block(
        "General", "NOT_AFFECTED", "Approved.", Assessed_By="rev",
        Justification="CODE_NOT_PRESENT",
    )
    instance = _instance("c-1", "v-1", state="NOT_AFFECTED", details=general,
                         justification="CODE_NOT_PRESENT")
    group = {**_group("CVE-2099-0002", instance), "tags": ["TeamB"]}
    _store(instance)
    task_id = _task([group], task_id="repair-guard-task")
    started = client.post(
        "/api/bulk-workflows/assessment-repair/preview-task",
        json={"task_id": task_id, "filters": {}},
    )
    preview = _wait(client, started.json()["task_id"])["result"]
    assert preview["selectable_group_ids"] == ["CVE-2099-0002"], preview

    later = general + "\n\n" + _block("TeamB", "EXPLOITABLE", "Saved meanwhile.", Ticket="B-9")
    original = base.guard_against_later_saves

    def save_in_between(context, payloads, skipped):
        guarded = original(context, payloads, skipped)
        assert all("expected_revision" in payload for _instance, payload in guarded)
        asyncio.run(main.cache_manager.persist_assessment_updates([{
            "project_uuid": PROJECT, "component_uuid": "c-1", "vulnerability_uuid": "v-1",
            "state": "EXPLOITABLE", "details": later, "suppressed": False,
        }], replace=True, origin="user", author="carol"))
        return guarded

    try:
        with patch.object(base, "guard_against_later_saves", save_in_between):
            applied = client.post(
                "/api/bulk-workflows/assessment-repair/apply",
                json={"task_id": task_id, "filters": {},
                      "group_ids": ["CVE-2099-0002"], "preview_token": preview["preview_token"],
                  "group_fingerprints": preview["group_fingerprints"]},
            )
        assert applied.status_code == 200, applied.text
        summary = applied.json()["summary"]
        assert summary["changed_since_preview"] == 1 and summary["queued"] == 0
        [stored] = main.cache_manager.get_cached_assessments([instance])
        assert "Saved meanwhile." in stored["details"] and "B-9" in stored["details"]
        assert "See global assessment." not in stored["details"]
    finally:
        main.tasks.pop(task_id, None)
