import asyncio
import logging
from datetime import UTC, datetime
from types import SimpleNamespace

from dtvp.analysis_queue_runtime import (
    AnalysisQueue,
    AnalysisQueueDeps,
    AnalysisQueueItem,
)
from dtvp.analysis_queue_services import (
    get_next_queued_item,
    prune_finished_queue_items,
    reindex_queue_items,
    start_analysis_queue_item,
)
from dtvp.analysis_queue_state_services import AnalysisQueueStateStore
from dtvp.runtime_value_services import parse_iso_timestamp


def _item(queue_id: str, *, status: str = "queued") -> AnalysisQueueItem:
    now = datetime.now(UTC).isoformat()
    return AnalysisQueueItem(
        queue_id=queue_id,
        vuln_id="CVE-2026-0001",
        component_name="example-component",
        submitted_by="alice",
        submitted_at=now,
        started_at=now if status == "running" else None,
        status=status,
    )


async def _unused_async(*_args, **_kwargs):
    return None


def _queue_deps(store: AnalysisQueueStateStore) -> AnalysisQueueDeps:
    return AnalysisQueueDeps(
        runtime_deps=SimpleNamespace(logger=logging.getLogger(__name__)),
        service_deps=object(),
        get_analysis_queue_ttl_seconds=lambda: 3600,
        get_analysis_queue_capacity=lambda: 1,
        parse_iso_timestamp=parse_iso_timestamp,
        utc_now=lambda: datetime.now(UTC),
        reindex_queue_items=reindex_queue_items,
        prune_finished_queue_items=prune_finished_queue_items,
        get_next_queued_item=get_next_queued_item,
        start_analysis_queue_item=start_analysis_queue_item,
        process_analysis_queue_item=_unused_async,
        run_analysis_queue_cleanup_loop=_unused_async,
        run_analysis_queue_worker=_unused_async,
        create_event=asyncio.Event,
        create_lock=asyncio.Lock,
        load_persisted_state=store.load,
        persist_state=store.save,
    )


def test_queue_store_round_trips_order_and_replaces_snapshot(tmp_path):
    path = tmp_path / "analysis-queue.sqlite"
    store = AnalysisQueueStateStore(path_provider=lambda: str(path))
    items = {
        "queued": _item("queued"),
        "hidden": _item("hidden", status="cancelled"),
    }

    store.save(items, ["queued"])

    loaded_items, loaded_order = store.load()
    assert loaded_order == ["queued"]
    assert set(loaded_items) == {"queued", "hidden"}
    assert loaded_items["queued"].submitted_by == "alice"
    assert path.stat().st_mode & 0o777 == 0o600

    store.save({"hidden": items["hidden"]}, [])
    replaced_items, replaced_order = store.load()
    assert set(replaced_items) == {"hidden"}
    assert replaced_order == []


def test_queue_restart_resumes_queued_and_marks_running_interrupted(tmp_path):
    store = AnalysisQueueStateStore(
        path_provider=lambda: str(tmp_path / "analysis-queue.sqlite")
    )
    store.save(
        {
            "queued": _item("queued"),
            "running": _item("running", status="running"),
        },
        ["queued", "running"],
    )

    queue = AnalysisQueue(_queue_deps(store))
    queue.reset_runtime_state()

    queued = queue.get("queued")
    interrupted = queue.get("running")
    assert queued is not None and queued.status == "queued"
    assert interrupted is not None and interrupted.status == "failed"
    assert interrupted.error == "Analysis interrupted by DTVP service restart."
    assert interrupted.finished_at is not None
    assert queue._event.is_set()

    persisted_items, _ = store.load()
    assert persisted_items["running"].status == "failed"


def test_queue_mutations_are_persisted(tmp_path):
    store = AnalysisQueueStateStore(
        path_provider=lambda: str(tmp_path / "analysis-queue.sqlite")
    )
    queue = AnalysisQueue(_queue_deps(store))
    queue.reset_runtime_state()

    submitted = queue.submit(
        vuln_id="CVE-2026-0002",
        component_name="demo",
        submitted_by="bob",
    )
    assert queue.cancel(submitted.queue_id)

    persisted_items, persisted_order = store.load()
    assert persisted_items[submitted.queue_id].status == "cancelled"
    assert persisted_order == []
