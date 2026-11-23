"""A bulk apply checks the preview per selected group (not the whole preview):
the background sync changes the findings all the time."""

import pytest
from fastapi import HTTPException

from dtvp.bulk_workflows.base import build_preview_token, group_fingerprints
from dtvp.general_api_routes import (
    BulkWorkflowApplyRequest,
    _bulk_workflow_error_detail,
    check_preview,
)


class Plugin:
    id = "example"
    version = 1

    def selectable_ids(self, preview):
        return [item["group_id"] for item in preview["items"] if item.get("selectable", True)]


def _preview(**changes):
    items = [
        {"group_id": "CVE-A", "finding_count": 2},
        {"group_id": "CVE-B", "finding_count": 1},
        {"group_id": "CVE-C", "finding_count": 3},
    ]
    for group_id, update in changes.items():
        items = [{**item, **update} if item["group_id"] == group_id else item for item in items]
    return {"items": items}


def _request(preview, selected, *, fingerprints=None, token=None, task_id="task-1"):
    plugin = Plugin()
    fingerprints = group_fingerprints(preview) if fingerprints is None else fingerprints
    return BulkWorkflowApplyRequest(
        task_id=task_id,
        group_ids=selected,
        preview_token=token or build_preview_token(plugin, task_id="task-1", filter_payload={}),
        group_fingerprints={group: fingerprints[group] for group in selected if group in fingerprints},
    )


def test_fingerprints_follow_the_item_not_its_position_or_key_order():
    preview = _preview()
    reordered = {"items": [
        {"finding_count": 1, "group_id": "CVE-B"},
        {"finding_count": 2, "group_id": "CVE-A"},
        {"finding_count": 3, "group_id": "CVE-C"},
    ]}
    assert group_fingerprints(preview) == group_fingerprints(reordered)
    assert group_fingerprints(preview)["CVE-A"] != group_fingerprints(
        _preview(**{"CVE-A": {"finding_count": 9}})
    )["CVE-A"]


def test_a_group_outside_the_selection_may_change():
    before = _preview()
    request = _request(before, ["CVE-A"])
    after = _preview(**{"CVE-B": {"finding_count": 4}})  # the sync wrote CVE-B

    assert check_preview(Plugin(), request, {}, after, "applying") == ["CVE-A"]


def test_a_selected_group_that_changed_is_listed_and_refused():
    before = _preview()
    request = _request(before, ["CVE-A", "CVE-B"])
    after = _preview(**{"CVE-B": {"finding_count": 4}})

    with pytest.raises(HTTPException) as refused:
        check_preview(Plugin(), request, {}, after, "applying")
    assert refused.value.status_code == 409
    assert refused.value.detail["code"] == "preview_changed"
    assert refused.value.detail["changed_groups"] == ["CVE-B"]
    assert "reload it before applying" in refused.value.detail["message"]


def test_a_selected_group_without_a_fingerprint_or_no_longer_selectable_is_listed():
    before = _preview()
    without = _request(before, ["CVE-A", "CVE-C"], fingerprints={"CVE-A": group_fingerprints(before)["CVE-A"]})
    with pytest.raises(HTTPException) as missing:
        check_preview(Plugin(), without, {}, before, "exporting")
    assert missing.value.detail["changed_groups"] == ["CVE-C"]
    assert "exporting" in missing.value.detail["message"]

    request = _request(before, ["CVE-A"])
    now_closed = _preview(**{"CVE-A": {"selectable": False}})
    with pytest.raises(HTTPException) as closed:
        check_preview(Plugin(), request, {}, now_closed, "applying")
    assert closed.value.detail["changed_groups"] == ["CVE-A"]


def test_a_different_task_or_filter_is_still_refused():
    before = _preview()
    request = _request(before, ["CVE-A"], task_id="task-2")
    with pytest.raises(HTTPException) as other_task:
        check_preview(Plugin(), request, {}, before, "applying")
    assert other_task.value.status_code == 409
    assert "stale" in other_task.value.detail and "changed_groups" not in str(other_task.value.detail)

    request = _request(before, ["CVE-A"])
    with pytest.raises(HTTPException) as other_filter:
        check_preview(Plugin(), request, {"analysis": ["EXPLOITABLE"]}, before, "applying")
    assert other_filter.value.status_code == 409 and "stale" in other_filter.value.detail


def test_the_structured_error_reaches_the_task_status():
    refused = HTTPException(status_code=409, detail={"code": "preview_changed", "changed_groups": ["CVE-B"]})
    assert _bulk_workflow_error_detail(refused) == {"code": "preview_changed", "changed_groups": ["CVE-B"]}
    assert _bulk_workflow_error_detail(HTTPException(status_code=409, detail="stale")) is None
    assert _bulk_workflow_error_detail(RuntimeError("boom")) is None


def _item_preview(**group_changes):
    """Preview items with the fields a workflow item carries (a repair's
    decision, the places of new findings)."""
    items = [
        {"group_id": "CVE-A", "finding_count": 2, "new_finding_places": ["app/x", "app/y"],
         "repairs": [{"id": "sync", "label": "Synchronize"}, {"id": "rescore", "label": "Rescore"}],
         "review": []},
        {"group_id": "CVE-B", "finding_count": 1, "new_finding_places": [], "repairs": [], "review": []},
    ]
    for group_id, update in group_changes.items():
        items = [{**item, **update} if item["group_id"] == group_id else item for item in items]
    return {"items": items}


def test_a_read_that_reorders_the_items_does_not_block_the_apply():
    before = _item_preview()
    request = _request(before, ["CVE-A"])
    reordered = _item_preview(**{"CVE-A": {
        "new_finding_places": ["app/y", "app/x"],
        "repairs": [{"id": "rescore", "label": "Rescore"}, {"id": "sync", "label": "Synchronize"}],
    }})

    assert check_preview(Plugin(), request, {}, reordered, "applying") == ["CVE-A"]


def test_a_real_change_in_the_selected_group_blocks_and_names_the_field():
    before = _item_preview()
    request = _request(before, ["CVE-A", "CVE-B"])
    request.group_items = {"CVE-A": before["items"][0], "CVE-B": before["items"][1]}
    after = _item_preview(**{"CVE-A": {"finding_count": 3}})

    with pytest.raises(HTTPException) as refused:
        check_preview(Plugin(), request, {}, after, "applying")
    detail = refused.value.detail
    assert detail["changed_groups"] == ["CVE-A"]
    assert detail["changes"] == {"CVE-A": [
        {"path": "finding_count", "before": "2", "after": "3"},
    ]}


def test_the_diff_says_where_a_list_changed_and_ignores_its_order():
    from dtvp.bulk_workflows.base import diff_items

    before = {"group_id": "CVE-A", "repairs": [{"id": "sync"}], "review": ["a"]}
    assert diff_items(before, {"group_id": "CVE-A", "repairs": [{"id": "sync"}], "review": ["a"]}) == []
    changes = diff_items(before, {"group_id": "CVE-A", "repairs": [{"id": "rescore"}], "review": ["a"]})
    assert [change["path"] for change in changes] == ["repairs[]"]
    assert diff_items(before, None)[0]["path"] == "(item)"
