import asyncio
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from dtvp.assessment_services import (
    AssessmentServiceDeps,
    apply_assessment_payloads,
    fetch_current_assessment_analyses,
    finalize_assessment_results,
)


def _deps(cache_manager=None) -> AssessmentServiceDeps:
    return AssessmentServiceDeps(
        cache_manager=cache_manager,
        logger=logging.getLogger(__name__),
        calculate_aggregated_state=lambda _details: "NOT_SET",
        process_assessment_details=lambda *_args, **_kwargs: ("", "NOT_SET"),
    )


def _payloads(count: int) -> list[tuple[dict, dict]]:
    return [
        (
            {
                "finding_uuid": f"finding-{index}",
                "vulnerability_uuid": f"vulnerability-{index}",
            },
            {
                "project_uuid": "project",
                "component_uuid": f"component-{index}",
                "vulnerability_uuid": f"vulnerability-{index}",
                "state": "NOT_AFFECTED",
                "details": "Not affected.",
                "suppressed": False,
            },
        )
        for index in range(count)
    ]


@pytest.mark.asyncio
async def test_assessment_reads_use_the_shared_io_limit(monkeypatch):
    active = 0
    max_active = 0

    class CacheManager:
        async def get_analysis(self, _client, **identity):
            nonlocal active, max_active
            active += 1
            max_active = max(max_active, active)
            await asyncio.sleep(0.005)
            active -= 1
            return {"analysisState": identity["vulnerability_uuid"]}

    monkeypatch.setenv("DTVP_ASSESSMENT_IO_CONCURRENCY", "2")
    request = SimpleNamespace(
        instances=[
            {
                "project_uuid": "project",
                "component_uuid": f"component-{index}",
                "vulnerability_uuid": f"vulnerability-{index}",
            }
            for index in range(12)
        ]
    )

    results = await fetch_current_assessment_analyses(
        _deps(CacheManager()),
        request,
        object(),
    )

    assert max_active == 2
    assert [result["analysisState"] for result in results] == [
        f"vulnerability-{index}" for index in range(12)
    ]


@pytest.mark.asyncio
async def test_assessment_writes_use_bounded_workers_and_report_progress():
    active = 0
    max_active = 0

    class Client:
        async def update_analysis(self, **_payload):
            nonlocal active, max_active
            active += 1
            max_active = max(max_active, active)
            await asyncio.sleep(0.005)
            active -= 1

    progress = []
    results = await apply_assessment_payloads(
        _deps(),
        Client(),
        _payloads(30),
        concurrency=3,
        max_attempts=1,
        progress_callback=lambda completed, total, result: progress.append(
            (completed, total, result["uuid"])
        ),
    )

    assert max_active == 3
    assert [result["uuid"] for result in results] == [
        f"finding-{index}" for index in range(30)
    ]
    assert [entry[0] for entry in progress] == list(range(1, 31))
    assert all(entry[1] == 30 for entry in progress)


@pytest.mark.asyncio
async def test_assessment_write_retries_transient_504_responses():
    request = httpx.Request("PUT", "https://dt.example.test/api/v1/analysis")
    gateway_timeout = httpx.HTTPStatusError(
        "gateway timeout",
        request=request,
        response=httpx.Response(504, request=request),
    )

    class Client:
        def __init__(self):
            self.calls = 0

        async def update_analysis(self, **_payload):
            self.calls += 1
            if self.calls < 3:
                raise gateway_timeout

    client = Client()
    results = await apply_assessment_payloads(
        _deps(),
        client,
        _payloads(1),
        concurrency=1,
        max_attempts=3,
        retry_base_delay_seconds=0,
    )

    assert client.calls == 3
    assert results == [
        {
            "status": "success",
            "uuid": "finding-0",
            "new_state": "NOT_AFFECTED",
            "new_details": "Not affected.",
            "attempts": 3,
        }
    ]


@pytest.mark.asyncio
async def test_failed_assessment_writes_are_queued_in_one_batch():
    cache_manager = AsyncMock()
    api_results = [
        {
            "status": "error",
            "uuid": instance["finding_uuid"],
            "error": "Dependency-Track unavailable",
            "payload": payload,
        }
        for instance, payload in _payloads(50)
    ]

    results = await finalize_assessment_results(
        _deps(cache_manager),
        api_results,
    )

    cache_manager.queue_analysis_updates.assert_awaited_once()
    queued_payloads = cache_manager.queue_analysis_updates.await_args.args[0]
    assert len(queued_payloads) == 50
    assert cache_manager.queue_analysis_updates.await_args.kwargs == {"replace": True}
    cache_manager.queue_analysis_update.assert_not_awaited()
    assert all(result["queued"] is True for result in results)
    assert all("payload" not in result for result in results)
