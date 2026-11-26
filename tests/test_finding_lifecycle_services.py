"""Rules and store of the finding lifecycle (synthetic data only)."""

import sqlite3

import pytest

from dtvp.finding_lifecycle_services import (
    FindingLifecycleStore,
    PresencePlan,
    ReportedIndex,
    choose_carry_over,
    classify_gone,
    get_finding_lifecycle_migrations_path,
    index_bom,
    plan_carry_over,
    plan_gone,
    reported_finding,
)
from dtvp.sqlite_migration_services import load_sqlite_migrations, run_sqlite_migrations


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


@pytest.mark.parametrize("deployed_version", [1, 3, 4])
def test_the_store_upgrades_deployed_dtvp_migrations(tmp_path, deployed_version):
    # Checksums shipped before the rename (main 7d9ced5d). Comments are part
    # of the checksum too; fresh-database tests cannot detect edits to them.
    deployed_checksums = {
        1: "5755986ea714d744f4f0b62c8a840da791bcf2d86c3c3f428b4618cd0deb5a05",
        2: "ccd0657234578b536e98390d23c23184dd6c288c2f581dc31820727715014b94",
        3: "ca07de0525b2561bfbae77e1ecb4954652b660b02e7d39f73d51ef44283b3897",
        4: "73566a2bf9a904955336ec53301db261ff3f0f4c539d1a3563b49bb3943f4206",
    }
    migrations = load_sqlite_migrations(get_finding_lifecycle_migrations_path())
    deployed_path = tmp_path / "deployed_migrations"
    deployed_path.mkdir()
    for migration in migrations:
        if migration.version <= deployed_version:
            (deployed_path / migration.path.name).write_text(migration.sql, encoding="utf-8")

    path = tmp_path / "dtvp.sqlite3"
    with sqlite3.connect(path) as connection:
        run_sqlite_migrations(connection, namespace="finding_lifecycle", migrations_path=deployed_path)
        connection.executemany(
            "UPDATE schema_migrations SET checksum = ? WHERE namespace = 'finding_lifecycle' AND version = ?",
            [(checksum, version) for version, checksum in deployed_checksums.items() if version <= deployed_version],
        )
        connection.execute(
            """INSERT INTO finding_presence (
                project_uuid, component_uuid, vulnerability_uuid, first_seen_at, status, gone_reason
            ) VALUES ('p1', 'c1', 'v1', '2026-11-01', 'gone', 'component_removed')"""
        )

    # Same entry point used by CacheManager during application startup.
    store = FindingLifecycleStore(str(path))
    assert store.backfill_once(lambda: []) == 0
    row = store.gone_row(("p1", "c1", "v1"))
    assert row["first_seen_at"] == "2026-11-01"
    assert row["gone_reason"] == "component_removed"
    assert FindingLifecycleStore(str(path)).backfill_once(lambda: []) is None
    with sqlite3.connect(path) as connection:
        applied = dict(connection.execute(
            "SELECT version, checksum FROM schema_migrations WHERE namespace = 'finding_lifecycle'"
        ))
    assert set(applied) == {migration.version for migration in migrations}
    assert {version: applied[version] for version in deployed_checksums} == deployed_checksums


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
    assert versions == [(1,), (2,), (3,), (4,)]


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
        "mass_disappearance": None,
    }
    assert described["trend"] == [
        {"day": "2026-11-02", "went": {"component_removed": 4, "replaced": 1}},
        {"day": "2026-11-03", "went": {"replaced": 1}},
    ]


# -- eighth reading: risky gone findings, mass disappearance, causes, aliases --

_EXPLOITABLE = (
    "--- [Team: D-Web] [State: EXPLOITABLE] [Assessed By: dana] [Ticket: VP-61182] ---\n"
    "Reachable through the sanitizer."
)
_NOT_AFFECTED = (
    "--- [Team: S-Web] [State: NOT_AFFECTED] [Assessed By: sam] "
    "[Justification: CODE_NOT_PRESENT] ---\nNot used."
)


def _value_record(state, details, sync_status="inactive"):
    return {"analysisState": state, "analysisDetails": details,
            "isSuppressed": False, "sync_status": sync_status, "revision": 1}


def test_an_exploitable_or_ticketed_gone_finding_needs_attention_whatever_the_reason(tmp_path):
    from dtvp.finding_lifecycle_services import describe_gone_findings

    store, gone = _store_with_gone(tmp_path)
    store.record_read("p1", [
        {**gone, "component_uuid": "c3", "carry_over": None, "gone_reason": "no_longer_matched"},
        {**gone, "component_uuid": "c4", "carry_over": None, "gone_reason": "no_longer_matched"},
        {**gone, "component_uuid": "c5", "carry_over": None, "gone_reason": "no_longer_matched"},
        {**gone, "component_uuid": "c6", "carry_over": "carried", "gone_reason": "replaced"},
    ])
    outbox = _Outbox({
        ("p1", "c3", "v1"): _value_record("EXPLOITABLE", _EXPLOITABLE),
        # A ticket alone, in a not-affected block.
        ("p1", "c4", "v1"): _value_record(
            "NOT_AFFECTED", _NOT_AFFECTED.replace("[Assessed By: sam]", "[Assessed By: sam] [Ticket: SR-1]")
        ),
        ("p1", "c5", "v1"): _value_record("NOT_AFFECTED", _NOT_AFFECTED),
        # Carried over: the assessment moved on.
        ("p1", "c6", "v1"): _value_record("EXPLOITABLE", _EXPLOITABLE, sync_status="superseded"),
    })

    flags = {
        f["component_uuid"]: (f["needs_attention"], f["tickets"])
        for f in describe_gone_findings(store, outbox, "p1")["findings"]
    }
    assert flags["c3"] == (True, ["VP-61182"])
    assert flags["c4"] == (True, ["SR-1"])
    assert flags["c5"] == (False, [])
    assert flags["c6"][0] is False


def test_risky_stays_marked_when_acknowledged_so_a_group_acknowledge_can_ask(tmp_path):
    from dtvp.finding_lifecycle_services import describe_gone_findings

    store, gone = _store_with_gone(tmp_path)
    store.record_read("p1", [
        {**gone, "component_uuid": "c3", "carry_over": None, "gone_reason": "no_longer_matched"},
        {**gone, "component_uuid": "c5", "carry_over": None, "gone_reason": "no_longer_matched"},
        {**gone, "component_uuid": "c6", "carry_over": "carried", "gone_reason": "replaced"},
    ])
    store.acknowledge("p1", [("c3", "v1")], by="rita", at="2026-11-22T10:00:00+00:00")
    outbox = _Outbox({
        ("p1", "c3", "v1"): _value_record("EXPLOITABLE", _EXPLOITABLE),
        ("p1", "c5", "v1"): _value_record("NOT_AFFECTED", _NOT_AFFECTED),
        ("p1", "c6", "v1"): _value_record("EXPLOITABLE", _EXPLOITABLE, sync_status="superseded"),
    })

    flags = {
        f["component_uuid"]: (f["risky"], f["needs_attention"])
        for f in describe_gone_findings(store, outbox, "p1")["findings"]
    }
    # Acknowledged: no longer needs attention, but still risky.
    assert flags["c3"] == (True, False)
    assert flags["c5"] == (False, False)
    # Carried over: the assessment moved on, nothing to warn about here.
    assert flags["c6"] == (False, False)


def test_a_mass_disappearance_is_flagged_by_count_or_share():
    from dtvp.finding_lifecycle_services import mass_disappearance

    assert mass_disappearance({"no_longer_matched": 1743}, 2355) == {
        "reason": "no_longer_matched", "count": 1743, "share": 0.425, "findings_before": 4098,
    }
    # 50 or more always; a tenth of a small project from 10 on.
    assert mass_disappearance({"no_longer_matched": 50}, 5000)["count"] == 50
    assert mass_disappearance({"no_longer_matched": 12}, 80)["share"] == 0.13
    assert mass_disappearance({"no_longer_matched": 9}, 10) is None
    assert mass_disappearance({"no_longer_matched": 49}, 5000) is None
    assert mass_disappearance({"replaced": 500}, 100) is None


def test_the_description_names_a_mass_disappearance_at_the_last_read(tmp_path):
    from dtvp.finding_lifecycle_services import describe_gone_findings

    store, _gone = _store_with_gone(tmp_path)
    store.record_read("p1", [], summary={
        "read_at": "2026-11-22T04:00:00+00:00", "went": {"no_longer_matched": 60},
        "returned": 0, "carried_over": 0, "not_carried": 0,
    })
    described = describe_gone_findings(store, _Outbox({}), "p1")
    assert described["last_read"]["mass_disappearance"]["count"] == 60
    assert described["summary"]["mass_disappearance"]["count"] == 60


def _cpe_bom(cpe, ref="c1", extra=()):
    return index_bom({"components": [
        {"bom-ref": ref, "name": "dompurify", "version": "3.2.7",
         "purl": "pkg:npm/dompurify@3.2.7", "cpe": cpe},
        *extra,
    ]})


def test_a_cpe_change_is_told_only_when_nothing_else_changed():
    from dtvp.finding_lifecycle_services import cpe_change

    old = _cpe_bom("cpe:2.3:a:cure53:dompurify:3.2.7:*:*:*:*:*:*:*")
    new = _cpe_bom("cpe:2.3:a:dompurify:dompurify:3.2.7:*:*:*:*:node.js:*:*")
    assert cpe_change("c1", old, new) == (
        "CPE changed from cpe:2.3:a:cure53:dompurify:3.2.7:*:*:*:*:*:*:* "
        "to cpe:2.3:a:dompurify:dompurify:3.2.7:*:*:*:*:node.js:*:*"
    )
    assert cpe_change("c1", old, old) is None
    assert cpe_change("c1", None, new) is None
    bumped = index_bom({"components": [{"bom-ref": "c1", "name": "dompurify", "version": "3.2.8",
                                        "purl": "pkg:npm/dompurify@3.2.8", "cpe": "x"}]})
    assert cpe_change("c1", old, bumped) is None


def test_a_bulk_loss_records_the_cpe_change_and_a_single_one_reads_no_bom():
    """Many findings no longer matched in one read: the BOM is read to tell
    why. A single one, decided by the findings alone, costs no BOM read."""
    old = _cpe_bom("cpe:2.3:a:cure53:dompurify:3.2.7")
    new = _cpe_bom("cpe:2.3:a:dompurify:dompurify:3.2.7")
    still = _finding("c1", vuln="v-other", vuln_id="GHSA-x4vx-rjvf-j5p4", name="dompurify", version="3.2.7")
    reads = []

    def read(index):
        def bom():
            reads.append(1)
            return index
        return bom

    rows = {("c1", f"v{n}"): _row("c1", name="dompurify", version="3.2.7", vuln=f"v{n}") for n in range(10)}
    plan = PresencePlan(rows={key: dict(row) for key, row in rows.items()})
    plan_gone(plan, "p", ReportedIndex([still]), {}, read_at="t1", last_seen_at="t0",
              bom=read(new), previous_bom=lambda: old)
    causes = {row["gone_cause"] for row in plan.rows.values() if row["status"] == "gone"}
    assert causes == {"CPE changed from cpe:2.3:a:cure53:dompurify:3.2.7 to cpe:2.3:a:dompurify:dompurify:3.2.7"}
    assert reads == [1]

    reads.clear()
    rows = {("c1", "v1"): _row("c1", name="dompurify", version="3.2.7")}
    plan = PresencePlan(rows={key: dict(row) for key, row in rows.items()})
    plan_gone(plan, "p", ReportedIndex([still]), {}, read_at="t1", last_seen_at="t0",
              bom=read(new), previous_bom=lambda: old)
    assert plan.rows[("c1", "v1")]["gone_reason"] == "no_longer_matched"
    assert plan.rows[("c1", "v1")]["gone_cause"] is None
    assert reads == []


def test_a_gone_cve_whose_advisory_is_still_reported_proposes_its_assessment(tmp_path):
    from dtvp.finding_lifecycle_services import alias_proposal, describe_gone_findings

    store, gone = _store_with_gone(tmp_path)
    store.record_read("p1", [
        {**gone, "component_uuid": "c7", "vulnerability_uuid": "v-cve", "vuln_id": "CVE-2026-65901",
         "gone_reason": "no_longer_matched", "carry_over": None},
        {**gone, "component_uuid": "c7", "vulnerability_uuid": "v-ghsa", "vuln_id": "GHSA-x4vx-rjvf-j5p4",
         "status": "reported", "gone_at": None, "gone_reason": None, "carry_over": None},
    ])
    aliases = {"CVE-2026-65901": {"GHSA-X4VX-RJVF-J5P4"}, "GHSA-X4VX-RJVF-J5P4": {"CVE-2026-65901"}}
    cve = _value_record("EXPLOITABLE", _EXPLOITABLE)
    ghsa = _value_record("NOT_AFFECTED", _NOT_AFFECTED, sync_status="synced")
    outbox = _Outbox({("p1", "c7", "v-cve"): cve, ("p1", "c7", "v-ghsa"): ghsa})

    [finding] = [f for f in describe_gone_findings(store, outbox, "p1", aliases)["findings"]
                 if f["vulnerability_uuid"] == "v-cve"]
    assert finding["alias"] == {
        "component_uuid": "c7", "vulnerability_uuid": "v-ghsa", "vuln_id": "GHSA-x4vx-rjvf-j5p4",
        "state": "NOT_AFFECTED", "tickets": [], "disagrees": True, "proposal": "blocks",
    }
    # The advisory keeps its state and gains the CVE's D-Web block with its
    # ticket as a historical block, pending review.
    blocks = alias_proposal(cve, ghsa)
    assert blocks["state"] == "NOT_AFFECTED"
    assert "[Team: D-Web]" in blocks["details"] and "VP-61182" in blocks["details"]
    assert "[Historical: yes]" in blocks["details"]
    assert blocks["details"].rstrip().endswith("[Status: Pending Review]")
    assert _NOT_AFFECTED.split("\n")[0] in blocks["details"]
    # An advisory without an assessment takes the CVE's, pending review.
    copy = alias_proposal(cve, None)
    assert (copy["kind"], copy["state"]) == ("copy", "EXPLOITABLE")
    assert copy["details"].startswith(_EXPLOITABLE) and copy["details"].endswith("[Status: Pending Review]")
    # Nothing to add: the advisory has the team already.
    assert alias_proposal(cve, _value_record("EXPLOITABLE", _EXPLOITABLE)) is None
    assert alias_proposal(_value_record("NOT_SET", ""), ghsa) is None


def test_reported_aliases_on_one_component_that_disagree_are_listed(tmp_path):
    from dtvp.finding_lifecycle_services import describe_gone_findings

    store, gone = _store_with_gone(tmp_path)
    reported = {**gone, "status": "reported", "gone_at": None, "gone_reason": None, "carry_over": None}
    store.record_read("p1", [
        {**reported, "component_uuid": "c9", "vulnerability_uuid": "va", "vuln_id": "CVE-2026-65913"},
        {**reported, "component_uuid": "c9", "vulnerability_uuid": "vb", "vuln_id": "GHSA-v9jr-rg53-9pgp"},
    ])
    aliases = {"CVE-2026-65913": {"GHSA-V9JR-RG53-9PGP"}, "GHSA-V9JR-RG53-9PGP": {"CVE-2026-65913"}}
    outbox = _Outbox({
        ("p1", "c9", "va"): _value_record("NOT_AFFECTED", _NOT_AFFECTED, "synced"),
        ("p1", "c9", "vb"): _value_record("EXPLOITABLE", _EXPLOITABLE, "synced"),
    })
    [disagreement] = describe_gone_findings(store, outbox, "p1", aliases)["alias_disagreements"]
    assert disagreement["component_uuid"] == "c9"
    assert [(f["vuln_id"], f["state"]) for f in disagreement["findings"]] == [
        ("CVE-2026-65913", "NOT_AFFECTED"), ("GHSA-v9jr-rg53-9pgp", "EXPLOITABLE"),
    ]



# -- review needs 2-4: every record followed, identity before reason, aliases --


def _lib_bom(*refs):
    return index_bom({"components": [
        {"bom-ref": ref, "name": "lib-a", "version": "1.0", "purl": "pkg:npm/lib-a@1.0"}
        for ref in refs
    ]})


def test_an_inactive_record_on_a_recreated_component_is_no_longer_matched_and_needs_attention(tmp_path):
    """CVE-2026-79651's case (a): a build before tracking retired the record
    (inactive); the component was recreated since and its identity is still
    in the BOM. The finding is followed, no longer matched, and flagged."""
    from dtvp.finding_lifecycle_services import (
        FindingLifecycleStore, describe_gone_findings,
    )

    key = ("p", "c-old", "v1")
    exploitable = _value_record("EXPLOITABLE", _EXPLOITABLE)
    plan = PresencePlan(rows={})
    reported = ReportedIndex([_finding("c-new", vuln="v2", vuln_id="CVE-2026-2")])
    plan_gone(plan, "p", reported, {key: exploitable}, read_at="t1", last_seen_at="t0",
              bom=lambda: _lib_bom("c-new"), previous_bom=lambda: _lib_bom("c-old"))

    row = plan.rows[("c-old", "v1")]
    assert (row["status"], row["gone_reason"]) == ("gone", "no_longer_matched")
    assert (row["predates_tracking"], row["first_seen_at"]) == (1, "")
    assert row["component_identity"] == "pkg:npm/lib-a"
    assert plan.went == {}  # not counted as gone at this read

    store = FindingLifecycleStore(str(tmp_path / "dtvp.sqlite3"))
    store.record_read("p", [plan.rows[k] for k in plan.changed])
    [finding] = describe_gone_findings(store, _Outbox({key: exploitable}), "p")["findings"]
    assert finding["needs_attention"] is True
    # Not "followed since" the unknown first sighting.
    assert store.export_gone_summary("p", _Outbox({key: exploitable}))["since"] is None


def test_an_earlier_component_removed_becomes_no_longer_matched_once_its_identity_is_known():
    """Case (b): followed without identity at the first tracked read, the
    old UUID gone from the BOM: "component removed". With the identity known
    and still in the BOM, it is no longer matched."""
    gone = {**_row("c-old"), "status": "gone", "gone_reason": "component_removed",
            "component_name": None, "component_version": None,
            "component_purl": None, "component_identity": None}
    plan = PresencePlan(rows={("c-old", "v1"): dict(gone)})
    reported = ReportedIndex([_finding("c-new", vuln="v2", vuln_id="CVE-2026-2")])
    plan_gone(plan, "p", reported, {}, read_at="t2", last_seen_at="t1",
              bom=lambda: _lib_bom("c-new"), previous_bom=lambda: _lib_bom("c-old"))
    row = plan.rows[("c-old", "v1")]
    assert row["component_identity"] == "pkg:npm/lib-a"
    assert row["gone_reason"] == "no_longer_matched"

    # Really removed (no component of that identity any more): it stays.
    plan = PresencePlan(rows={("c-old", "v1"): dict(gone)})
    plan_gone(plan, "p", ReportedIndex([]), {}, read_at="t2", last_seen_at="t1",
              bom=lambda: index_bom({"components": []}), previous_bom=lambda: _lib_bom("c-old"))
    assert plan.rows[("c-old", "v1")]["gone_reason"] == "component_removed"


def test_untracked_records_are_backfilled_once(tmp_path):
    from dtvp.finding_lifecycle_services import FindingLifecycleStore

    store = FindingLifecycleStore(str(tmp_path / "dtvp.sqlite3"))
    store.record_read("p", [_row("c-known")])
    records = [
        (("p", "c-known", "v1"), {"sync_status": "synced"}),  # has a row: kept
        (("p", "c-old", "v1"), {"sync_status": "inactive"}),
        (("p", "c-gone", "v1"), {"sync_status": "pending"}),
        (("p", "c-moved", "v1"), {"sync_status": "superseded"}),  # moved on: not followed
    ]
    names = {"c-old": {"component_name": "lib-a", "component_version": "1.0",
                       "component_purl": "pkg:npm/lib-a@1.0", "component_identity": "pkg:npm/lib-a"}}

    made = store.backfill_untracked_records_once(
        lambda: records, lambda project, component: names.get(component), at="t9"
    )
    assert made == 2
    rows = store.presence("p")
    assert rows[("c-known", "v1")]["status"] == "reported"
    old = rows[("c-old", "v1")]
    assert (old["status"], old["gone_reason"], old["predates_tracking"], old["first_seen_at"]) == (
        "gone", "undetermined", 1, "",
    )
    assert old["component_name"] == "lib-a"
    assert rows[("c-gone", "v1")]["component_name"] is None
    assert ("c-moved", "v1") not in rows
    # Once only.
    assert store.backfill_untracked_records_once(lambda: records, lambda p, c: None, at="t10") is None


def test_a_gone_cve_proposes_for_its_advisory_on_the_recreated_component(tmp_path):
    """The GHSA is reported on a component of the same identity and version
    under another UUID: proposed, pending review; a conflict when the GHSA is
    assessed differently."""
    from dtvp.finding_lifecycle_services import FindingLifecycleStore, describe_gone_findings

    store = FindingLifecycleStore(str(tmp_path / "dtvp.sqlite3"))
    cve = {**_row("c-old", vuln="v-cve"), "vuln_id": "CVE-2026-79651", "status": "gone",
           "gone_reason": "no_longer_matched", "gone_at": "t1"}
    ghsa = {**_row("c-new", vuln="v-ghsa"), "vuln_id": "GHSA-aaaa-bbbb-cccc"}
    other = {**_row("c-other", version="2.0", vuln="v-ghsa"), "vuln_id": "GHSA-aaaa-bbbb-cccc"}
    store.record_read("p", [cve, ghsa, other])
    aliases = {"CVE-2026-79651": {"GHSA-AAAA-BBBB-CCCC"}, "GHSA-AAAA-BBBB-CCCC": {"CVE-2026-79651"}}
    exploitable = _value_record("EXPLOITABLE", _EXPLOITABLE)

    unassessed = describe_gone_findings(
        store, _Outbox({("p", "c-old", "v-cve"): exploitable}), "p", aliases
    )
    [finding] = unassessed["findings"]
    assert finding["alias"]["component_uuid"] == "c-new"  # same version, not c-other
    assert (finding["alias"]["proposal"], finding["alias"]["disagrees"]) == ("copy", False)

    assessed = describe_gone_findings(store, _Outbox({
        ("p", "c-old", "v-cve"): exploitable,
        ("p", "c-new", "v-ghsa"): _value_record("NOT_AFFECTED", _NOT_AFFECTED, "synced"),
    }), "p", aliases)
    [finding] = assessed["findings"]
    assert (finding["alias"]["proposal"], finding["alias"]["disagrees"]) == ("blocks", True)


def test_the_export_summary_counts_what_needs_attention(tmp_path):
    store, gone = _store_with_gone(tmp_path)
    store.record_read("p1", [{**gone, "component_uuid": "c3", "carry_over": None,
                              "gone_reason": "no_longer_matched"}])
    outbox = _Outbox({("p1", "c3", "v1"): _value_record("EXPLOITABLE", _EXPLOITABLE)})
    assert store.export_gone_summary("p1", outbox)["attention"] == 1
    store.acknowledge("p1", [("c3", "v1")], by="rita", at="t1")
    assert store.export_gone_summary("p1", outbox)["attention"] == 0
    assert store.export_gone_summary("p1")["attention"] == 0



# -- after review of #327 -----------------------------------------------------


def _rf(component, name, version, purl, vuln="v1", vuln_id="CVE-1"):
    return reported_finding({
        "component": {"uuid": component, "name": name, "version": version, "purl": purl},
        "vulnerability": {"uuid": vuln, "vulnId": vuln_id},
    })


def _plan_and_carry(previous, now, targets, records):
    before = index_bom({"components": previous})
    current = index_bom({"components": now})
    reported = ReportedIndex(targets)
    plan = PresencePlan(rows={})
    plan_gone(plan, "p", reported, records, read_at="t1", last_seen_at="t0",
              bom=lambda: current, previous_bom=lambda: before)
    carry = plan_carry_over(
        "p", targets, reported, records, plan.rows,
        unrecorded_per_vulnerability={"v1": len(targets)},
        bom=lambda: current, previous_bom=lambda: before,
    )
    return plan, carry


def _inactive(state="NOT_AFFECTED"):
    return {"analysisState": state, "analysisDetails": "x", "isSuppressed": False,
            "sync_status": "inactive", "revision": 1}


def test_a_name_alone_does_not_carry_by_identity_to_another_groups_package():
    """Components without a package URL: the identity is only the name. Two
    packages of that name now report the vulnerability: nothing is carried
    (the by-vulnerability rule needs exactly one candidate)."""
    previous = [{"bom-ref": "c-old", "name": "foo", "version": "1.0", "group": "a"}]
    now = [{"bom-ref": "c2", "name": "foo", "version": "9", "group": "b"},
           {"bom-ref": "c3", "name": "foo", "version": "1", "group": "c"}]
    targets = [_rf("c2", "foo", "9", None), _rf("c3", "foo", "1", None)]
    _plan, carry = _plan_and_carry(previous, now, targets, {("p", "c-old", "v1"): _inactive()})
    assert carry.carries == []


def test_a_name_alone_is_never_a_recreation_without_review():
    previous = [{"bom-ref": "c-old", "name": "foo", "version": "1.0", "group": "a"}]
    now = [{"bom-ref": "c3", "name": "foo", "version": "1.0", "group": "c"}]
    _plan, carry = _plan_and_carry(
        previous, now, [_rf("c3", "foo", "1.0", None)], {("p", "c-old", "v1"): _inactive("EXPLOITABLE")}
    )
    # At most carried by vulnerability and name, pending review; never as a
    # recreation of the same package.
    assert all(not item.recreated for item in carry.carries)
    assert all(item.origin == "carried-over-by-vulnerability" for item in carry.carries)


def test_another_version_of_a_package_is_no_recreation():
    previous = [{"bom-ref": "c-old", "name": "lib", "version": "1.0", "purl": "pkg:npm/lib@1.0"}]
    now = [{"bom-ref": "c2", "name": "lib", "version": "5.0", "purl": "pkg:npm/lib@5.0"}]
    _plan, carry = _plan_and_carry(
        previous, now, [_rf("c2", "lib", "5.0", "pkg:npm/lib@5.0")], {("p", "c-old", "v1"): _inactive()}
    )
    assert [item.recreated for item in carry.carries] == [False]


def test_a_tracked_removal_stays_when_another_version_appears():
    """component_removed told with the identity known: a later version of
    the package in the BOM does not make it no longer matched."""
    row = {**_row("c-old", name="lib", version="1.0"), "status": "gone",
           "gone_reason": "component_removed", "predates_tracking": 0}
    row["component_purl"], row["component_identity"] = "pkg:npm/lib@1.0", "pkg:npm/lib"
    bom = index_bom({"components": [
        {"bom-ref": "c9", "name": "lib", "version": "3.0", "purl": "pkg:npm/lib@3.0"},
    ]})
    plan = PresencePlan(rows={("c-old", "v1"): row})
    plan_gone(plan, "p", ReportedIndex([_rf("c9", "lib", "3.0", "pkg:npm/lib@3.0", vuln="v2", vuln_id="CVE-2")]),
              {}, read_at="t5", last_seen_at="t4", bom=lambda: bom, previous_bom=lambda: bom)
    assert plan.rows[("c-old", "v1")]["gone_reason"] == "component_removed"


def test_a_predating_removal_needs_the_same_version_to_be_upgraded():
    row = {**_row("c-old", name="lib", version="1.0"), "status": "gone",
           "gone_reason": "component_removed", "predates_tracking": 1}
    row["component_purl"], row["component_identity"] = "pkg:npm/lib@1.0", "pkg:npm/lib"
    other_version = index_bom({"components": [
        {"bom-ref": "c9", "name": "lib", "version": "3.0", "purl": "pkg:npm/lib@3.0"},
    ]})
    plan = PresencePlan(rows={("c-old", "v1"): dict(row)})
    plan_gone(plan, "p", ReportedIndex([]), {}, read_at="t5", last_seen_at="t4",
              bom=lambda: other_version, previous_bom=lambda: other_version)
    assert plan.rows[("c-old", "v1")]["gone_reason"] == "component_removed"

    same = index_bom({"components": [
        {"bom-ref": "c-new", "name": "lib", "version": "1.0", "purl": "pkg:npm/lib@1.0"},
    ]})
    plan = PresencePlan(rows={("c-old", "v1"): dict(row)})
    plan_gone(plan, "p", ReportedIndex([]), {}, read_at="t5", last_seen_at="t4",
              bom=lambda: same, previous_bom=lambda: same)
    assert plan.rows[("c-old", "v1")]["gone_reason"] == "no_longer_matched"


def test_a_tracked_removal_costs_no_bom_read_at_later_reads():
    row = {**_row("c-old", name="lib", version="1.0"), "status": "gone",
           "gone_reason": "component_removed", "predates_tracking": 0}
    row["component_purl"], row["component_identity"] = "pkg:npm/lib@1.0", "pkg:npm/lib"
    stored = index_bom({"components": [
        {"bom-ref": "c-new", "name": "lib", "version": "1.0", "purl": "pkg:npm/lib@1.0"},
    ]})
    reads = []
    plan = PresencePlan(rows={("c-old", "v1"): row})
    plan_gone(plan, "p", ReportedIndex([]), {}, read_at="t5", last_seen_at="t4",
              bom=lambda: reads.append(1) or stored, previous_bom=lambda: stored)
    assert reads == []


def test_a_returning_finding_loses_its_cause_and_a_predating_row_is_no_return():
    from dtvp.finding_lifecycle_services import plan_reported

    gone = {**_row("c1"), "status": "gone", "gone_reason": "no_longer_matched",
            "gone_cause": "CPE changed from a to b", "predates_tracking": 0}
    predating = {**_row("c2"), "status": "gone", "gone_reason": "undetermined",
                 "predates_tracking": 1, "first_seen_at": ""}
    rows = {("c1", "v1"): gone, ("c2", "v1"): predating}
    plan = plan_reported("p", rows, ReportedIndex([_finding("c1"), _finding("c2")]), "t9")
    assert plan.rows[("c1", "v1")]["gone_cause"] is None
    assert plan.returned == 1  # c1 only


def test_followed_since_leaves_predating_rows_out(tmp_path):
    from dtvp.finding_lifecycle_services import FindingLifecycleStore

    store = FindingLifecycleStore(str(tmp_path / "dtvp.sqlite3"))
    store.record_read("p", [
        {**_row("c1"), "first_seen_at": "2026-11-20T00:00:00+00:00"},
        {**_row("c2"), "status": "gone", "gone_reason": "undetermined", "gone_at": "t1",
         "first_seen_at": "2026-01-01T00:00:00+00:00", "predates_tracking": 1},
    ])
    assert store.export_gone_summary("p")["since"] == "2026-11-20T00:00:00+00:00"


def test_the_backfill_skips_versions_without_known_findings(tmp_path):
    from dtvp.finding_lifecycle_services import FindingLifecycleStore

    store = FindingLifecycleStore(str(tmp_path / "dtvp.sqlite3"))
    store.record_read("known", [_row("c-known")])
    made = store.backfill_untracked_records_once(
        lambda: [(("known", "c-old", "v1"), {"sync_status": "inactive"}),
                 (("unread", "c-x", "v1"), {"sync_status": "synced"})],
        lambda project, component: None,
        at="t9",
    )
    assert made == 1
    assert store.presence("unread") == {}



def _tracked(component, name, version):
    """A row of a finding River saw reported, without a package URL."""
    return {**_row(component, name=name, version=version), "vuln_id": "CVE-1",
            "component_purl": None, "component_identity": name, "predates_tracking": 0}


def _synced(state="NOT_AFFECTED"):
    return {"analysisState": state, "analysisDetails": "x", "isSuppressed": False,
            "sync_status": "synced", "revision": 1}


def _follow(rows, targets, records, bom_components):
    now = index_bom({"components": bom_components})
    reported = ReportedIndex(targets)
    plan = PresencePlan(rows=rows)
    plan_gone(plan, "p", reported, records, read_at="t1", last_seen_at="t0",
              bom=lambda: now, previous_bom=lambda: None)
    return plan_carry_over(
        "p", targets, reported, records, plan.rows,
        unrecorded_per_vulnerability={"v1": len(targets)}, bom=lambda: now,
    )


def test_tracked_components_without_package_urls_still_carry_when_recreated():
    """The reviewer's case: foo and bar, told by the findings, recreated
    under new UUIDs. Both carry over as recreations, as before."""
    rows = {("o1", "v1"): _tracked("o1", "foo", "1.0"), ("o2", "v1"): _tracked("o2", "bar", "1.0")}
    targets = [_rf("n1", "foo", "1.0", None), _rf("n2", "bar", "1.0", None)]
    carry = _follow(
        rows, targets, {("p", "o1", "v1"): _synced(), ("p", "o2", "v1"): _synced()},
        [{"bom-ref": "n1", "name": "foo", "version": "1.0"},
         {"bom-ref": "n2", "name": "bar", "version": "1.0"}],
    )
    assert sorted((item.target, item.origin, item.recreated) for item in carry.carries) == [
        (("p", "n1", "v1"), "carried-over-recreated", True),
        (("p", "n2", "v1"), "carried-over-recreated", True),
    ]

    one = _follow(
        {("o1", "v1"): _tracked("o1", "foo", "1.0")}, [_rf("n1", "foo", "1.0", None)],
        {("p", "o1", "v1"): _synced()}, [{"bom-ref": "n1", "name": "foo", "version": "1.0"}],
    )
    assert [(item.origin, item.recreated) for item in one.carries] == [("carried-over-recreated", True)]


def test_a_recreation_without_package_urls_needs_a_unique_target():
    """Two findings of the vulnerability on components of that name and
    version: carried, but pending review (not a recreation)."""
    rows = {("o1", "v1"): _tracked("o1", "foo", "1.0")}
    targets = [_rf("n1", "foo", "1.0", None), _rf("n2", "foo", "1.0", None)]
    carry = _follow(rows, targets, {("p", "o1", "v1"): _synced()},
                    [{"bom-ref": "n1", "name": "foo", "version": "1.0"},
                     {"bom-ref": "n2", "name": "foo", "version": "1.0"}])
    assert carry.carries and all(not item.recreated for item in carry.carries)


def test_a_replaced_assessment_no_rule_carries_is_left_for_a_person():
    """Never dropped silently: a name taken from a BOM for an old record,
    two packages of that name now: nothing carried, so undetermined."""
    previous = [{"bom-ref": "c-old", "name": "foo", "version": "1.0", "group": "a"}]
    now = [{"bom-ref": "c2", "name": "foo", "version": "9", "group": "b"},
           {"bom-ref": "c3", "name": "foo", "version": "1", "group": "c"}]
    targets = [_rf("c2", "foo", "9", None), _rf("c3", "foo", "1", None)]
    plan, carry = _plan_and_carry(previous, now, targets, {("p", "c-old", "v1"): _inactive()})
    assert carry.carries == [] and carry.conflicts == []
    assert [keys for _target, keys in carry.undetermined] == [[("p", "c-old", "v1")]]
