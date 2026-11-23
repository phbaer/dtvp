"""A component missing from the BOM is "removed" only when its identity is
known: without it DTVP cannot tell a removal from a recreation (Dependency-
Track recreated components nightly before tracking)."""

from dtvp.finding_lifecycle_services import (
    REASON_COMPONENT_REMOVED,
    REASON_UNDETERMINED,
    STATUS_GONE,
    FindingLifecycleStore,
    ReportedIndex,
    _new_row,
    classify_gone,
    index_bom,
    reported_finding,
)

BOM = index_bom({"components": [{"bom-ref": "c-other", "name": "lib-b", "version": "2.0",
                                 "purl": "pkg:npm/lib-b@2.0"}]})


def _row(component, *, identity=None, predating=1):
    return {"component_uuid": component, "vulnerability_uuid": "v1", "vuln_id": None,
            "component_identity": identity, "predates_tracking": predating}


def test_an_unnamed_row_missing_from_the_bom_is_undetermined_predating_or_not():
    reasons = classify_gone(
        [_row("c-old", predating=1), _row("c-new", predating=0)], ReportedIndex([]), BOM,
    )
    assert reasons[("c-old", "v1")] == (REASON_UNDETERMINED, [])
    assert reasons[("c-new", "v1")] == (REASON_UNDETERMINED, [])


def test_a_known_identity_missing_from_the_bom_is_still_removed():
    reasons = classify_gone([_row("c-old", identity="pkg:npm/lib-a")], ReportedIndex([]), BOM)
    assert reasons[("c-old", "v1")] == (REASON_COMPONENT_REMOVED, [])


def _stored_gone(store, component, *, identity, predating):
    finding = reported_finding({
        "component": {"uuid": component, "name": "lib-a" if identity else None,
                      "version": "1.0", "purl": "pkg:npm/lib-a@1.0" if identity else None},
        "vulnerability": {"uuid": "v1", "vulnId": "CVE-2026-1"},
    })
    row = _new_row("p1", finding, "2026-11-01T00:00:00+00:00")
    row.update(status=STATUS_GONE, gone_at="2026-11-02T00:00:00+00:00",
               gone_reason=REASON_COMPONENT_REMOVED, component_identity=identity,
               predates_tracking=predating)
    if not identity:
        row.update(component_name=None, component_purl=None, component_version=None)
    store.record_read("p1", [row])


def test_stored_unfounded_removals_are_repaired_once_and_exported_as_predating(tmp_path):
    store = FindingLifecycleStore(str(tmp_path / "lifecycle.sqlite3"))
    _stored_gone(store, "c-unnamed", identity=None, predating=1)
    _stored_gone(store, "c-named", identity="pkg:npm/lib-a", predating=0)

    assert store.repair_unfounded_removals() == 1
    assert store.repair_unfounded_removals() == 0  # idempotent

    rows = store.presence("p1")
    assert rows[("c-unnamed", "v1")]["gone_reason"] == REASON_UNDETERMINED
    assert rows[("c-named", "v1")]["gone_reason"] == REASON_COMPONENT_REMOVED
    summary = store.export_gone_summary("p1")
    # export_findings_gone_predating, not export_findings_gone.
    assert summary["predating"] == {REASON_UNDETERMINED: 1}
    assert summary["gone"] == {REASON_COMPONENT_REMOVED: 1}
