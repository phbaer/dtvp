from dtvp.runtime_state import DTVPRuntimeState


def test_runtime_state_instances_do_not_share_mutable_collections():
    first = DTVPRuntimeState()
    second = DTVPRuntimeState()

    first.grouped_tasks["task-1"] = {"status": "running"}
    first.archive_tasks["archive-1"] = {"status": "completed"}
    first.tmrescore_project_cache["project-1"] = {"proposal": {}}
    first.tmrescore_analysis_tasks["analysis-1"] = {"status": "queued"}
    first.startup["status"] = "failed"

    assert second.grouped_tasks == {}
    assert second.archive_tasks == {}
    assert second.tmrescore_project_cache == {}
    assert second.tmrescore_analysis_tasks == {}
    assert second.startup["status"] == "ready"
