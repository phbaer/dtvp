"""Bounded read-only native workspace workload measurements, never release acceptance."""

import argparse
import asyncio
import math
import os
import time
from collections import Counter
from urllib.parse import quote

import httpx


async def probe(client, *, project, version, requests=20, concurrency=2):
    if not 1 <= requests <= 200 or not 1 <= concurrency <= 10:
        raise ValueError("Probe supports 1–200 requests and 1–10 concurrent readers")
    path = (
        f"/api/v3/projects/{quote(project, safe='')}/versions/{quote(version, safe='')}/workspace"
    )
    initial = await client.get(path, params={"limit": 1})
    initial.raise_for_status()
    state = initial.json()["state"]
    pending = asyncio.Queue()
    for index in range(requests):
        pending.put_nowait(index)
    observations = []
    started = time.monotonic()

    async def worker():
        while not pending.empty():
            pending.get_nowait()
            then = time.monotonic()
            try:
                response = await client.get(path, params={"limit": 25, "expected": state})
                status = str(response.status_code)
                payload = response.json() if response.is_success else None
                consistent = isinstance(payload, dict) and payload.get("state") == state
            except httpx.HTTPError, ValueError:
                status, consistent = "transport_or_response_error", False
            observations.append(
                {
                    "milliseconds": (time.monotonic() - then) * 1000,
                    "status": status,
                    "consistent": consistent,
                }
            )

    # A deadline bounds the whole probe, independently of per-request timeouts.
    try:
        async with asyncio.timeout(120):
            await asyncio.gather(*(worker() for _ in range(min(concurrency, requests))))
        expired = False
    except TimeoutError:
        expired = True
    duration = time.monotonic() - started
    latencies = sorted(item["milliseconds"] for item in observations)

    def percentile(fraction):
        return (
            round(latencies[max(0, math.ceil(len(latencies) * fraction) - 1)], 3)
            if latencies
            else None
        )

    return {
        "format": "dtvp.workspace-workload-probe/1",
        "project_id": project,
        "version": version,
        "state": state,
        "requested": requests,
        "completed": len(observations),
        "concurrency": concurrency,
        "deadline_exceeded": expired,
        "consistent_responses": sum(item["consistent"] for item in observations),
        "status_counts": dict(sorted(Counter(item["status"] for item in observations).items())),
        "duration_seconds": round(duration, 3),
        "latency_ms": {
            "p50": percentile(0.5),
            "p95": percentile(0.95),
            "maximum": round(latencies[-1], 3) if latencies else None,
        },
        "acceptance": "observations_only_no_production_capacity_or_release_verdict",
        "limitations": [
            "Read-only workload; does not measure imports, jobs, mixed-team writes or production hardware capacity.",
            "One exact version head is pinned; concurrent publication yields conflicts, not silently mixed measurements.",
            "Client and network latency are included; select deployment-specific budgets separately.",
        ],
    }


def main():
    import json

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8900")
    parser.add_argument("--token-env", default="DTVP_API_TOKEN")
    parser.add_argument("--persona", help="Explicit synthetic playground login instead of a token")
    parser.add_argument("--project", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--requests", type=int, default=20)
    parser.add_argument("--concurrency", type=int, default=2)
    args = parser.parse_args()
    token = os.getenv(args.token_env)
    if token and args.persona:
        parser.error("Select either a read credential or a playground persona")

    async def run():
        headers = {"Authorization": "Bearer " + token} if token else {}
        async with httpx.AsyncClient(
            base_url=args.url, headers=headers, timeout=10, follow_redirects=False
        ) as client:
            if args.persona:
                response = await client.post(
                    "/api/v2/playground/login", json={"persona": args.persona}
                )
                response.raise_for_status()
                me = await client.get("/api/v2/me")
                me.raise_for_status()
                if me.json().get("playground") is not True:
                    raise ValueError("Persona authentication requires an isolated playground")
            return await probe(
                client,
                project=args.project,
                version=args.version,
                requests=args.requests,
                concurrency=args.concurrency,
            )

    result = asyncio.run(run())
    print(json.dumps(result, indent=2))
    if result["consistent_responses"] != result["requested"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
