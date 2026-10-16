"""Read probes pin a head, respect reader bounds and expose conflicts/errors."""

import asyncio

import httpx
import pytest

from scripts.knowledge_workload_probe import probe


def test_probe_is_read_only_bounded_and_does_not_mix_advanced_heads():
    async def run():
        active, peak, calls = 0, 0, []

        async def handle(request):
            nonlocal active, peak
            calls.append(request)
            assert request.method == "GET"
            if len(calls) == 1:
                return httpx.Response(200, json={"state": "a" * 64})
            assert request.url.params["expected"] == "a" * 64
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.001)
            active -= 1
            return (
                httpx.Response(409, json={"detail": "Head advanced"})
                if len(calls) > 4
                else httpx.Response(200, json={"state": "a" * 64})
            )

        async with httpx.AsyncClient(
            base_url="http://test", transport=httpx.MockTransport(handle)
        ) as client:
            result = await probe(
                client, project="product/name", version="7.1.1", requests=8, concurrency=2
            )
        assert peak == 2
        assert len(calls) == 9
        assert result["completed"] == result["requested"] == 8
        assert result["consistent_responses"] < 8
        assert result["status_counts"]["409"] > 0
        assert result["latency_ms"]["p95"] >= result["latency_ms"]["p50"]
        assert result["acceptance"].startswith("observations_only")

    asyncio.run(run())


def test_probe_rejects_excessive_load_before_sending_requests():
    async def run():
        async with httpx.AsyncClient(
            base_url="http://test",
            transport=httpx.MockTransport(
                lambda request: pytest.fail("Request sent before bound checks")
            ),
        ) as client:
            for requests, concurrency in ((201, 1), (1, 11), (0, 1)):
                with pytest.raises(ValueError, match="supports"):
                    await probe(
                        client, project="p", version="v", requests=requests, concurrency=concurrency
                    )

    asyncio.run(run())
