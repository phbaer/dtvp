"""Version override tags (ADR 0010, step 4): a field of the finding that
every writer keeps, and that a save cannot change."""

import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from dtvp import main
from dtvp.assessment_model import (
    RESERVED_DETAIL_PATTERN,
    canonical_assessment_text,
    parse_assessment,
    preserve_version_override,
    render_assessment,
    version_override,
    with_version_override,
)
from dtvp.assessment_outbox_services import AssessmentOutboxStore
from dtvp.bulk_workflows.assessment_repair import _with_rescoring
from dtvp.bulk_workflows.incomplete_sync import _keep_finding_values
from dtvp.logic import process_assessment_details, remove_assessment_blocks
from tests.test_mcp_server import ARGS, _token, project, service  # noqa: F401

LTS = {"label": "LTS 2.x", "reason": "Backported fix"}
TAGS = "[Version Override: LTS 2.x] [Override Reason: Backported fix]"
GENERAL = (
    "--- [Team: General] [State: NOT_AFFECTED] [Assessed By: alice] "
    "[Justification: NOT_SET] ---\nNot reachable."
)
ALPHA = (
    "--- [Team: Alpha] [State: NOT_AFFECTED] [Assessed By: bob] "
    "[Justification: NOT_SET] ---\nAlpha checked."
)
TAGGED = f"[Response: UPDATE] {TAGS}\n\n{GENERAL}\n\n{ALPHA}"


# -- the field -----------------------------------------------------------------


def test_the_tags_are_a_field_and_not_free_text():
    fields = parse_assessment("NOT_AFFECTED", f"{TAGS}\n\nA note.\n\n{GENERAL}", False)

    assert fields["version_override"] == LTS
    assert fields["free_text"] == "A note."
    assert render_assessment(fields) == f"{TAGS}\n\nA note.\n\n{GENERAL}"
    assert canonical_assessment_text("NOT_AFFECTED", TAGGED) == TAGGED


@pytest.mark.parametrize(
    "text",
    [
        "[Version Override: base]",
        "[Version Override: Ambiguous]",
        "[Version Override: no/slash]",
        "[Version Override: " + "x" * 41 + "]",
    ],
)
def test_an_invalid_or_reserved_label_stays_text(text):
    fields = parse_assessment("NOT_SET", text, False)

    assert fields["version_override"] is None
    assert fields["free_text"] == text


def test_a_label_without_a_valid_reason_has_no_reason():
    assert version_override("[Version Override: L] [Override Reason: a --- b]") == {
        "label": "L", "reason": None,
    }


def test_with_and_preserve_change_nothing_else():
    plain = f"[Response: UPDATE]\n\n{GENERAL}"
    assert with_version_override(plain, LTS) == TAGGED.replace(f"\n\n{ALPHA}", "")
    assert with_version_override(TAGGED, None) == f"[Response: UPDATE]\n\n{GENERAL}\n\n{ALPHA}"
    assert with_version_override(TAGGED, LTS) == TAGGED
    assert preserve_version_override(GENERAL, TAGGED) == f"{TAGS}\n\n{GENERAL}"
    assert preserve_version_override(TAGGED, GENERAL) == f"[Response: UPDATE]\n\n{GENERAL}\n\n{ALPHA}"


def test_agent_and_copied_text_cannot_carry_a_marker():
    assert RESERVED_DETAIL_PATTERN.search("see [Version Override: x]")
    assert RESERVED_DETAIL_PATTERN.search("[Override Reason")


# -- writers ------------------------------------------------------------------


@pytest.mark.parametrize("team", ["Alpha", "General", "Beta"])
def test_a_team_save_keeps_the_marker(team):
    details, _state = process_assessment_details(
        "New finding text.", "carol", "REVIEWER", team=team,
        state="NOT_AFFECTED", existing_details=TAGGED,
    )
    assert version_override(details) == LTS
    assert details.startswith(f"[Response: UPDATE] {TAGS}")


def test_a_save_over_legacy_text_keeps_the_marker_out_of_the_general_block():
    details, _state = process_assessment_details(
        "Assessed.", "carol", "REVIEWER", team="Alpha",
        state="NOT_AFFECTED", existing_details=f"{TAGS}\n\nOld free text.",
    )
    assert version_override(details) == LTS
    assert details.startswith(TAGS)


@pytest.mark.parametrize("team", ["Alpha", "General", None])
def test_a_delete_keeps_the_marker(team):
    details = remove_assessment_blocks(TAGGED, team)
    assert version_override(details) == LTS
    if team is None:
        assert details == TAGS


def test_synchronize_keeps_each_findings_marker():
    assert version_override(_keep_finding_values(GENERAL, TAGGED, None)) == LTS
    assert version_override(_keep_finding_values(GENERAL, GENERAL, None)) is None


def test_a_repair_rebuild_keeps_each_findings_marker():
    rebuild = _with_rescoring(
        GENERAL,
        [{"analysis_details": TAGGED}, {"analysis_details": GENERAL}],
    )
    assert version_override(rebuild(TAGGED)) == LTS
    assert version_override(rebuild(GENERAL)) is None


# -- save use case and MCP ---------------------------------------------------------


async def _tag_all(findings):
    await main.cache_manager.persist_assessment_updates(
        [
            {
                "project_uuid": key[0], "component_uuid": key[1],
                "vulnerability_uuid": key[2], "state": "IN_TRIAGE",
                "details": with_version_override("Checking.", LTS),
                "suppressed": False,
            }
            for key in findings
        ],
        replace=True,
    )


KEYS = [("p1", "component-1", "vuln-1"), ("p2", "component-2", "vuln-1")]


async def test_an_mcp_save_keeps_the_stored_marker(service):
    token = _token()
    await service.get_vulnerability(token, project="TestApp", vulnerability_id="CVE-2026-0001")
    await _tag_all(KEYS)
    preview = await service.preview_assessment(token, **ARGS)
    await service.save_assessment(
        token, **ARGS, expected_revisions=preview["expected_revisions"]
    )

    for key in KEYS:
        stored = main.cache_manager.get_assessment_overlay(*key)
        assert version_override(stored["analysisDetails"]) == LTS


async def test_a_save_cannot_change_the_marker(service):
    from dtvp.assessment_use_cases import (
        AssessmentRequest,
        AssessmentValidationError,
        _validate_version_override_change,
    )

    stored = [with_version_override(GENERAL, LTS)]
    same = AssessmentRequest(
        instances=[], state="NOT_AFFECTED", details=with_version_override(GENERAL, {**LTS, "label": "lts  2.X"})
    )
    _validate_version_override_change(same, stored)  # same label, normalised
    _validate_version_override_change(AssessmentRequest(instances=[], state="NOT_AFFECTED", details=GENERAL), stored)
    for other in ({"label": "Other", "reason": "x"}, {**LTS, "reason": "Different"}):
        with pytest.raises(AssessmentValidationError):
            _validate_version_override_change(
                AssessmentRequest(instances=[], state="NOT_AFFECTED", details=with_version_override(GENERAL, other)),
                stored,
            )
    with pytest.raises(AssessmentValidationError):
        _validate_version_override_change(
            AssessmentRequest(instances=[], state="NOT_AFFECTED", details=with_version_override(GENERAL, LTS)),
            [GENERAL],
        )


# -- stored fields and adoption ---------------------------------------------------

KEY = ("project", "component", "vulnerability")


def _later():
    return datetime.now(UTC) + timedelta(seconds=5)


def test_the_fields_table_has_the_marker(tmp_path):
    store = AssessmentOutboxStore(str(tmp_path / "dtvp.sqlite3"))
    store.reconcile_remote(
        {KEY: {"state": "NOT_AFFECTED", "details": GENERAL, "suppressed": False}},
        fetched_at=_later(),
    )
    assert store.get_fields(KEY)["version_override"] is None
    with sqlite3.connect(tmp_path / "dtvp.sqlite3") as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(assessment_fields)")}
    assert {"version_override", "version_override_reason"} <= columns


def test_an_adopted_value_with_a_marker_is_reviewed(tmp_path):
    store = AssessmentOutboxStore(str(tmp_path / "dtvp.sqlite3"))
    source = {"state": "NOT_AFFECTED", "details": TAGGED, "suppressed": False}

    outcomes = store.reconcile_remote({KEY: source}, fetched_at=_later())

    assert outcomes["adopted"] == [KEY]
    newest, first = store.list_revisions(KEY)
    assert (first["revision"], first["origin"], first["analysisDetails"]) == (0, "import", TAGGED)
    assert (newest["revision"], newest["origin"]) == (1, "import-review")
    assert newest["analysisDetails"] == f"{TAGGED}\n\n[Status: Pending Review]"
    fields = store.get_fields(KEY)
    assert fields["version_override"] == LTS and fields["pending_review"] is True
    [due] = store.list_due(_later() + timedelta(days=1))
    assert due["revision"] == 1
    assert store.get_overlay(KEY)["sync_status"] == "pending"


def test_an_adopted_value_without_a_marker_is_not_reviewed(tmp_path):
    store = AssessmentOutboxStore(str(tmp_path / "dtvp.sqlite3"))
    store.reconcile_remote(
        {KEY: {"state": "NOT_AFFECTED", "details": GENERAL, "suppressed": False}},
        fetched_at=_later(),
    )
    assert [r["origin"] for r in store.list_revisions(KEY)] == ["import"]
    assert store.list_due(_later() + timedelta(days=1)) == []
