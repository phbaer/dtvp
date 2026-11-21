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
    assert versions == [(1,), (2,)]


def test_a_finding_gone_at_export_is_marked_once(tmp_path):
    store = FindingLifecycleStore(str(tmp_path / "dtvp.sqlite3"))
    store.backfill_once(lambda: [("p1", {"component": {"uuid": "c1"},
                                         "vulnerability": {"uuid": "v1"}}, "t0")])
    assert store.mark_gone(("p1", "c1", "v1"), reason="missing_at_export", at="t1")
    assert not store.mark_gone(("p1", "c1", "v1"), reason="missing_at_export", at="t2")
    assert not store.mark_gone(("p1", "c9", "v1"), reason="missing_at_export", at="t2")
    assert store.gone_counts("p1") == {"missing_at_export": 1}
    assert store.gone_row(("p1", "c1", "v1"))["gone_at"] == "t1"


# -- acknowledgements, attention, statistics --------------------------------


def _store_with_gone(tmp_path):
    from dtvp.finding_lifecycle_services import FindingLifecycleStore

    store = FindingLifecycleStore(str(tmp_path / "dtvp.sqlite3"))
    base = {
        "vuln_id": "CVE-2026-1", "component_name": "lib-a", "component_version": "1.0",
        "component_purl": "pkg:npm/lib-a@1.0", "component_identity": "pkg:npm/lib-a",
        "first_seen_at": "2026-11-01T00:00:00+00:00", "last_seen_at": None,
        "gone_reason": None, "successor_component_uuid": None, "carry_over": None,
        "returned_at": None,
    }
    gone = {**base, "component_uuid": "c1", "vulnerability_uuid": "v1", "status": "gone",
            "gone_at": "2026-11-02T00:00:00+00:00", "gone_reason": "component_removed",
            "carry_over": "undetermined"}
    reported = {**base, "component_uuid": "c2", "vulnerability_uuid": "v1",
                "status": "reported", "gone_at": None}
    store.record_read("p1", [gone, reported])
    return store, gone


def test_an_acknowledgement_is_shared_and_kept_while_the_finding_stays_gone(tmp_path):
    store, gone = _store_with_gone(tmp_path)

    # Only gone findings; unknown and reported ones are skipped.
    assert store.acknowledge(
        "p1", [("c1", "v1"), ("c2", "v1"), ("c9", "v1")], by="rita", at="t1"
    ) == 1
    assert store.acknowledge("p1", [("c1", "v1")], by="rita", at="t2") == 0
    row = store.presence("p1")[("c1", "v1")]
    assert (row["acknowledged_by"], row["acknowledged_at"]) == ("rita", "t1")

    # A later read that still has it gone keeps the acknowledgement.
    store.record_read("p1", [{**gone, "gone_reason": "no_longer_matched"}])
    assert store.presence("p1")[("c1", "v1")]["acknowledged_by"] == "rita"

    # Withdrawn.
    assert store.acknowledge("p1", [("c1", "v1")], by=None, at="t3") == 1
    row = store.presence("p1")[("c1", "v1")]
    assert (row["acknowledged_by"], row["acknowledged_at"]) == (None, None)


def test_a_finding_reported_again_loses_its_acknowledgement(tmp_path):
    store, gone = _store_with_gone(tmp_path)
    store.acknowledge("p1", [("c1", "v1")], by="rita", at="t1")

    store.record_read("p1", [{**gone, "status": "reported", "returned_at": "t2"}])
    assert store.presence("p1")[("c1", "v1")]["acknowledged_by"] is None
    # Gone again: it asks again.
    store.record_read("p1", [{**gone, "gone_at": "2026-11-05T00:00:00+00:00"}])
    assert store.presence("p1")[("c1", "v1")]["acknowledged_by"] is None


class _Outbox:
    def __init__(self, records):
        self.records = records

    def get_overlay(self, key):
        return self.records.get(key)


def test_only_an_uncarried_assessment_with_a_value_needs_attention(tmp_path):
    from dtvp.finding_lifecycle_services import describe_gone_findings

    store, gone = _store_with_gone(tmp_path)
    more = [
        # Assessments differ: needs attention.
        {**gone, "component_uuid": "c3", "carry_over": "conflict"},
        # Carried: nothing to do.
        {**gone, "component_uuid": "c4", "carry_over": "carried",
         "gone_reason": "replaced", "successor_component_uuid": "c2"},
        # Undetermined, but the record is blank.
        {**gone, "component_uuid": "c5"},
        # Undetermined, no record at all.
        {**gone, "component_uuid": "c6"},
        # A real replacement by another version.
        {**gone, "component_uuid": "c7", "carry_over": "own_assessment",
         "gone_reason": "replaced", "successor_component_uuid": "c8",
         "gone_at": "2026-11-03T00:00:00+00:00"},
        {**gone, "component_uuid": "c8", "component_version": "1.1",
         "status": "reported", "gone_at": None, "gone_reason": None,
         "carry_over": None},
    ]
    store.record_read("p1", more)
    value = {"analysisState": "NOT_AFFECTED", "analysisDetails": "x",
             "isSuppressed": False, "sync_status": "inactive", "revision": 1}
    outbox = _Outbox({
        ("p1", "c1", "v1"): value,
        ("p1", "c3", "v1"): value,
        ("p1", "c4", "v1"): {**value, "sync_status": "superseded"},
        ("p1", "c5", "v1"): {**value, "analysisState": "NOT_SET", "analysisDetails": ""},
        ("p1", "c7", "v1"): value,
    })
    store.acknowledge("p1", [("c3", "v1")], by="rita", at="t1")

    described = describe_gone_findings(store, outbox, "p1")
    flags = {f["component_uuid"]: f["needs_attention"] for f in described["findings"]}
    assert flags == {"c1": True, "c3": False, "c4": False, "c5": False, "c6": False, "c7": False}
    by_uuid = {f["component_uuid"]: f for f in described["findings"]}
    assert by_uuid["c4"]["recreated"] is True  # lib-a@1.0 again
    assert by_uuid["c7"]["recreated"] is False  # lib-a@1.1
    assert by_uuid["c3"]["acknowledged_by"] == "rita"
    assert described["summary"] == {
        "by_reason": {"component_removed": 4, "recreated": 1, "replaced": 1},
        "by_carry_over": {"carried": 1, "conflict": 1, "own_assessment": 1, "undetermined": 3},
        "needs_attention": 1,
        "acknowledged": 1,
    }
    assert described["trend"] == [
        {"day": "2026-11-02", "went": {"component_removed": 4, "replaced": 1}},
        {"day": "2026-11-03", "went": {"replaced": 1}},
    ]
