"""The preview and the apply of one task, on the same data and without any
sync, must compute the same items: the apply refuses a group only when the
data changed."""

from dtvp.bulk_workflows.assessment_repair import build_assessment_repair_preview
from dtvp.bulk_workflows.base import BulkWorkflowContext
from tests.test_bulk_workflows import _group_with_new_version


def _context(group, include=()):
    return BulkWorkflowContext(
        task_id="task-1", groups=[group], user="reviewer",
        include_new_findings=frozenset(include),
    )


def test_preview_and_apply_compute_the_same_item_for_the_same_data():
    group = _group_with_new_version()
    preview = build_assessment_repair_preview(_context(group), lambda: {})
    applied_side = build_assessment_repair_preview(_context(group), lambda: {})
    assert applied_side["items"] == preview["items"]


def test_including_the_new_findings_at_apply_changes_the_item_the_preview_showed():
    group = _group_with_new_version()
    shown = build_assessment_repair_preview(_context(group), lambda: {})["items"][0]
    applied = build_assessment_repair_preview(
        _context(group, include=[group["id"]]), lambda: {},
    )["items"][0]
    print("\nSHOWN  ", {k: shown[k] for k in ("finding_count", "requires_review")}, [r["id"] for r in shown["repairs"]])
    print("APPLIED", {k: applied[k] for k in ("finding_count", "requires_review")}, [r["id"] for r in applied["repairs"]])
    assert applied != shown


def test_an_apply_that_includes_the_new_findings_accepts_the_preview_as_shown():
    from dtvp.bulk_workflows.base import build_preview_token, group_fingerprints, preview_as_shown
    from dtvp.general_api_routes import BulkWorkflowApplyRequest, check_preview

    class Plugin:
        id = "assessment-repair"
        version = 1

        def selectable_ids(self, preview):
            return [item["group_id"] for item in preview["items"]]

    group = _group_with_new_version()
    shown = build_assessment_repair_preview(_context(group), lambda: {})
    request = BulkWorkflowApplyRequest(
        task_id="task-1",
        group_ids=[group["id"]],
        preview_token=build_preview_token(Plugin(), task_id="task-1", filter_payload={}),
        group_fingerprints=group_fingerprints(shown),
        group_items={item["group_id"]: item for item in shown["items"]},
        include_new_findings=[group["id"]],
    )
    apply_context = _context(group, include=request.include_new_findings)

    # The check compares with the preview as shown, not with the one that
    # the includes would make (which differs: finding_count 1 -> 2).
    base = build_assessment_repair_preview(preview_as_shown(apply_context), lambda: {})
    assert check_preview(Plugin(), request, {}, base, "applying") == [group["id"]]
    assert build_assessment_repair_preview(apply_context, lambda: {})["items"] != shown["items"]


def test_the_item_does_not_depend_on_the_time_of_the_build(monkeypatch):
    """The repair stage takes the clock for the dates it writes; the item the
    reviewer sees must not move with it (a preview and an apply run at
    different times)."""
    import dtvp.bulk_workflows.assessment_repair as repair

    group = _group_with_new_version()
    first = build_assessment_repair_preview(_context(group), lambda: {})["items"]

    real_time = repair.time.time

    class Later:
        @staticmethod
        def time():
            return real_time() + 7 * 86400

    monkeypatch.setattr(repair, "time", Later)
    assert build_assessment_repair_preview(_context(group), lambda: {})["items"] == first
