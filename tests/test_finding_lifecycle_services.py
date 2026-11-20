"""Rules and store of the finding lifecycle (synthetic data only)."""

import sqlite3

import pytest

from dtvp.finding_lifecycle_services import (
    FindingLifecycleStore,
    PresencePlan,
    ReportedIndex,
    choose_carry_over,
    classify_gone,
    index_bom,
    plan_carry_over,
    plan_gone,
    reported_finding,
)


# -- why a finding went -----------------------------------------------------


def _finding(component, vuln="v1", vuln_id="CVE-2026-1", version="1.0", name="lib-a"):
    return reported_finding(
        {
            "component": {
                "uuid": component,
                "name": name,
                "version": version,
                "purl": f"pkg:npm/{name}@{version}",
            },
            "vulnerability": {"uuid": vuln, "vulnId": vuln_id},
        }
    )


def _gone(component, vuln="v1", vuln_id="CVE-2026-1", identity="pkg:npm/lib-a"):
    return {
        "component_uuid": component,
        "vulnerability_uuid": vuln,
        "vuln_id": vuln_id,
        "component_identity": identity,
    }


def test_a_finding_on_a_recreated_component_was_replaced():
    reported = ReportedIndex([_finding("c-new", version="1.1"), _finding("c-new-2")])
    reasons = classify_gone([_gone("c-old")], reported, None)
    assert reasons[("c-old", "v1")] == ("replaced", ["c-new", "c-new-2"])


def test_the_same_identifier_under_another_vulnerability_uuid_matches():
    reported = ReportedIndex([_finding("c-new", vuln="v9")])
    assert classify_gone([_gone("c-old")], reported, None)[("c-old", "v1")][0] == "replaced"


def test_a_component_still_reporting_other_findings_no_longer_matches():
    reported = ReportedIndex([_finding("c1", vuln="v2", vuln_id="CVE-2026-2")])
    assert classify_gone([_gone("c1")], reported, None)[("c1", "v1")] == (
        "no_longer_matched", [],
    )


def test_a_component_still_in_the_bom_no_longer_matches_and_one_gone_was_removed():
    reported = ReportedIndex([])
    bom = index_bom({"components": [{"bom-ref": "c1", "name": "lib-a",
                                     "components": [{"bom-ref": "c2", "name": "lib-b"}]}]})
    rows = [_gone("c1"), _gone("c2", identity="lib-b"), _gone("c3", identity="lib-c")]
    reasons = classify_gone(rows, reported, bom)
    assert reasons[("c1", "v1")][0] == "no_longer_matched"
    assert reasons[("c2", "v1")][0] == "no_longer_matched"  # nested
    assert reasons[("c3", "v1")][0] == "component_removed"
    assert classify_gone(rows, reported, None)[("c3", "v1")][0] == "undetermined"


def test_a_component_still_in_the_bom_was_not_replaced():
    reported = ReportedIndex([_finding("c-new", version="1.1")])
    bom = index_bom({"components": [{"bom-ref": "c-old"}, {"bom-ref": "c-new"}]})
    assert classify_gone([_gone("c-old")], reported, bom)[("c-old", "v1")][0] == "no_longer_matched"


def _row(component, name="lib-a", version="1.0", vuln="v1", status="reported", reason=None):
    item = _finding(component, vuln=vuln, version=version, name=name)
    return {
        "project_uuid": "p",
        "component_uuid": component,
        "vulnerability_uuid": vuln,
        "vuln_id": item.vuln_id,
        "component_name": name,
        "component_version": version,
        "component_purl": item.component_purl,
        "component_identity": item.component_identity,
        "first_seen_at": "t0",
        "status": status,
        "gone_at": None,
        "last_seen_at": None,
        "gone_reason": reason,
        "successor_component_uuid": None,
        "carry_over": None,
        "returned_at": None,
    }


def _record(status="inactive", state="NOT_AFFECTED", details="Not reachable."):
    return {
        "sync_status": status,
        "analysisState": state,
        "analysisDetails": details,
        "isSuppressed": False,
        "revision": 1,
    }


def test_replaced_needs_the_bom_to_lack_the_old_component():
    """Two versions in the BOM; the vulnerability moves from one to the
    other. The findings alone suggest a replacement; the BOM says no."""
    rows = {("c1", "v1"): _row("c1"), ("c2", "v1"): _row("c2", version="2.0")}
    reported = ReportedIndex([_finding("c2", version="2.0")])
    calls = []

    def bom(*refs):
        def read():
            calls.append(refs)
            return index_bom({"components": [{"bom-ref": ref} for ref in refs]})
        return read

    plan = PresencePlan(rows={key: dict(row) for key, row in rows.items()})
    plan_gone(plan, "p", reported, {}, read_at="t1", last_seen_at="t0", bom=bom("c1", "c2"))
    assert plan.rows[("c1", "v1")]["gone_reason"] == "no_longer_matched"
    assert calls == [("c1", "c2")]

    plan = PresencePlan(rows={key: dict(row) for key, row in rows.items()})
    plan_gone(plan, "p", reported, {}, read_at="t1", last_seen_at="t0", bom=bom("c2"))
    row = plan.rows[("c1", "v1")]
    assert (row["gone_reason"], row["successor_component_uuid"]) == ("replaced", "c2")

    plan = PresencePlan(rows={key: dict(row) for key, row in rows.items()})
    plan_gone(plan, "p", reported, {}, read_at="t1", last_seen_at="t0", bom=lambda: None)
    assert plan.rows[("c1", "v1")]["gone_reason"] == "undetermined"


def test_only_a_replaced_finding_hands_its_assessment_on():
    target = _finding("c2", version="2.0")
    reported = ReportedIndex([target])
    records = {("p", "c1", "v1"): _record()}
    no_bom = lambda: None  # noqa: E731

    for reason, carried in (("no_longer_matched", False), ("undetermined", False), ("replaced", True)):
        rows = {("c1", "v1"): _row("c1", status="gone", reason=reason)}
        plan = plan_carry_over(
            "p", [target], reported, records, rows,
            unrecorded_per_vulnerability={"v1": 1}, bom=no_bom,
        )
        assert bool(plan.carries) is carried, reason


def test_a_record_without_identity_is_carried_only_to_a_component_of_its_name():
    """A record from before identities: its component is gone from the BOM,
    and one finding of the vulnerability has no record."""
    target = _finding("c9", name="libbar", version="2.0")
    reported = ReportedIndex([target])
    records = {("p", "c1", "v1"): _record()}
    bom = lambda: index_bom({"components": [{"bom-ref": "c9"}]})  # noqa: E731

    def plan_with(previous):
        return plan_carry_over(
            "p", [target], reported, records, {},
            unrecorded_per_vulnerability={"v1": 1},
            bom=bom,
            previous_bom=lambda: index_bom(previous),
        )

    other = plan_with({"components": [{"bom-ref": "c1", "name": "libfoo"}]})
    assert (other.carries, other.conflicts, other.undetermined) == ([], [], [])

    unknown = plan_with(None)
    assert unknown.carries == []
    assert unknown.undetermined == [(("p", "c9", "v1"), [("p", "c1", "v1")])]
    assert unknown.not_carried == 1

    same = plan_with({"components": [{"bom-ref": "c1", "name": "LibBar", "version": "1.0"}]})
    [carry] = same.carries
    assert (carry.target, carry.candidates, carry.origin) == (
        ("p", "c9", "v1"), [("p", "c1", "v1")], "carried-over-by-vulnerability",
    )
    assert carry.components[("p", "c1", "v1")]["component_version"] == "1.0"


def test_an_unusable_bom_is_no_bom():
    assert index_bom(None) is None and index_bom(["x"]) is None


def test_carry_over_needs_agreement_except_for_the_review_marker():
    value = {"state": "NOT_AFFECTED", "details": "Fine.", "suppressed": False}
    marked = {**value, "details": "Fine.\n\n[Status: Pending Review]"}
    assert choose_carry_over([value, marked]) == value
    assert choose_carry_over([value, {**value, "details": "Other."}]) is None
    assert choose_carry_over([]) is None


# -- the store --------------------------------------------------------------


def test_the_store_migrates_and_backfills_once(tmp_path):
    path = str(tmp_path / "dtvp.sqlite3")
    calls = []

    def rows():
        calls.append(1)
        yield (
            "p1",
            {"component": {"uuid": "c1", "name": "lib-a", "version": "1.0",
                           "purl": "pkg:npm/lib-a@1.0"},
             "vulnerability": {"uuid": "v1", "vulnId": "CVE-2026-1"}},
            "2026-11-01T00:00:00+00:00",
        )

    store = FindingLifecycleStore(path)
    assert store.backfill_once(rows) == 1
    assert store.backfill_once(rows) is None
    assert FindingLifecycleStore(path).backfill_once(rows) is None
    assert calls == [1]
    row = store.presence("p1")[("c1", "v1")]
    assert (row["status"], row["component_identity"], row["first_seen_at"]) == (
        "reported", "pkg:npm/lib-a", "2026-11-01T00:00:00+00:00",
    )
    with sqlite3.connect(path) as connection:
        versions = connection.execute(
            "SELECT version FROM schema_migrations WHERE namespace = 'finding_lifecycle'"
        ).fetchall()
    assert versions == [(1,)]


def test_a_finding_gone_at_export_is_marked_once(tmp_path):
    store = FindingLifecycleStore(str(tmp_path / "dtvp.sqlite3"))
    store.backfill_once(lambda: [("p1", {"component": {"uuid": "c1"},
                                         "vulnerability": {"uuid": "v1"}}, "t0")])
    assert store.mark_gone(("p1", "c1", "v1"), reason="missing_at_export", at="t1")
    assert not store.mark_gone(("p1", "c1", "v1"), reason="missing_at_export", at="t2")
    assert not store.mark_gone(("p1", "c9", "v1"), reason="missing_at_export", at="t2")
    assert store.gone_counts("p1") == {"missing_at_export": 1}
    assert store.gone_row(("p1", "c1", "v1"))["gone_at"] == "t1"
