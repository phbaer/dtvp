#!/usr/bin/env python3
"""Reproducible cold and cached grouped-vulnerability query benchmark."""

import argparse
import gc
import json
import math
import os
import platform
import statistics
import sys
import time
import tracemalloc
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from dtvp.python_runtime_services import get_python_runtime_status
from dtvp.task_group_query_services import (
    build_task_group_query_index,
    query_task_groups,
)


SCHEMA_VERSION = "dtvp.group-query-benchmark/v1"


def build_synthetic_groups(count: int, *, buckets: int) -> list[dict[str, Any]]:
    states = ("NOT_SET", "IN_TRIAGE", "EXPLOITABLE", "RESOLVED")
    relationships = ("DIRECT", "TRANSITIVE", "UNKNOWN")
    lifecycles = ("OPEN", "OPEN", "ASSESSED", "INCOMPLETE")
    teams = ("Platform", "Runtime", "Applications", "Security")
    return [
        {
            "id": f"CVE-2026-{index:07d}",
            "title": (
                f"Synthetic finding search-bucket-{index % buckets} "
                f"package-family-{index % 97}"
            ),
            "description": "Deterministic grouped-query benchmark record",
            "aliases": [f"GHSA-{index:04x}-{index % 4096:04x}"],
            "tags": [teams[index % len(teams)]],
            "assignees": [f"reviewer-{index % 12}"],
            "cvss_score": float(index % 101) / 10,
            "rescored_cvss": float((index * 7) % 101) / 10,
            "list_metadata": {
                "lifecycle": lifecycles[index % len(lifecycles)],
                "is_open": index % len(lifecycles) < 2,
                "is_pending": index % 19 == 0,
                "technical_state": states[index % len(states)],
                "component_names": [
                    f"library-{index % 503}",
                    f"module-{index % 61}",
                ],
                "versions": [f"{1 + index % 4}.{index % 20}.0"],
                "dependency_relationship": relationships[
                    index % len(relationships)
                ],
                "cvss_version_mismatch": index % 23 == 0,
                "attributed_on_ms_values": [1_700_000_000_000 + index],
            },
            "affected_versions": [],
        }
        for index in range(count)
    ]


def _query_options(
    *,
    query_number: int,
    buckets: int,
    include_counts: bool,
    context_prefix: str,
) -> dict[str, Any]:
    return {
        "q": f"search-bucket-{query_number % buckets}",
        "lifecycle": [],
        "inconsistency_reason": [],
        "analysis": [],
        "tag": "",
        "team": "",
        "vuln_id": "",
        "component": "",
        "assignee": "",
        "dependency": [],
        "versions": [],
        "cvss_mismatch": False,
        "attributed_before_days": None,
        "attribution_mode": "older",
        "tmrescore": [],
        "tmrescore_proposal_ids": [],
        "automatic_assessment": [],
        "automatic_assessment_ids": [],
        "sort_by": "severity",
        "sort_order": "desc",
        "offset": 0,
        "limit": 50,
        "include_counts": include_counts,
        "dynamic_context_key": f"{context_prefix}-{query_number}",
    }


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(
        0,
        min(len(ordered) - 1, math.ceil(len(ordered) * percentile) - 1),
    )
    return ordered[index]


def _measure_queries(
    index: dict[str, Any],
    *,
    concurrency: int,
    query_count: int,
    options_factory: Callable[[int], dict[str, Any]],
) -> dict[str, Any]:
    def execute(query_number: int) -> float:
        started_at = time.perf_counter()
        query_task_groups(index, **options_factory(query_number))
        return (time.perf_counter() - started_at) * 1000

    started_at = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        latencies_ms = list(executor.map(execute, range(query_count)))
    wall_seconds = time.perf_counter() - started_at
    return {
        "queries": query_count,
        "wall_seconds": round(wall_seconds, 6),
        "throughput_qps": round(query_count / wall_seconds, 3),
        "latency_ms": {
            "mean": round(statistics.fmean(latencies_ms), 3),
            "p50": round(_percentile(latencies_ms, 0.50), 3),
            "p95": round(_percentile(latencies_ms, 0.95), 3),
            "max": round(max(latencies_ms), 3),
        },
    }


def _benchmark_group_count(
    group_count: int,
    *,
    buckets: int,
    concurrencies: list[int],
    queries_per_worker: int,
    cached_queries_per_worker: int,
    include_counts: bool,
) -> dict[str, Any]:
    groups = build_synthetic_groups(group_count, buckets=buckets)
    gc.collect()
    tracemalloc.start()
    allocation_before, _ = tracemalloc.get_traced_memory()
    build_started_at = time.perf_counter()
    index = build_task_group_query_index(groups)
    build_seconds = time.perf_counter() - build_started_at
    allocation_after, peak_allocation = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # Prime the shared sort order so the query cases measure filtering/facets,
    # which is the work repeated for each new UI search and filter combination.
    query_task_groups(
        index,
        **_query_options(
            query_number=0,
            buckets=buckets,
            include_counts=False,
            context_prefix="sort-prime",
        ),
    )

    results: list[dict[str, Any]] = []
    for concurrency in concurrencies:
        cold_count = max(concurrency, concurrency * queries_per_worker)
        cold_prefix = f"cold-{group_count}-{concurrency}"
        cold = _measure_queries(
            index,
            concurrency=concurrency,
            query_count=cold_count,
            options_factory=lambda query_number, prefix=cold_prefix: _query_options(
                query_number=query_number,
                buckets=buckets,
                include_counts=include_counts,
                context_prefix=prefix,
            ),
        )

        cached_options = _query_options(
            query_number=0,
            buckets=buckets,
            include_counts=include_counts,
            context_prefix=f"cached-{group_count}-{concurrency}",
        )
        query_task_groups(index, **cached_options)
        cached_count = max(concurrency, concurrency * cached_queries_per_worker)
        cached = _measure_queries(
            index,
            concurrency=concurrency,
            query_count=cached_count,
            options_factory=lambda _query_number, options=cached_options: options,
        )
        results.append(
            {
                "concurrency": concurrency,
                "cold": cold,
                "cached": cached,
            }
        )

    return {
        "groups": group_count,
        "index": {
            "build_seconds": round(build_seconds, 6),
            "retained_python_mib": round(
                max(0, allocation_after - allocation_before) / 1024**2,
                3,
            ),
            "peak_python_mib": round(
                max(0, peak_allocation - allocation_before) / 1024**2,
                3,
            ),
        },
        "results": results,
    }


def run_benchmark(
    *,
    group_counts: list[int],
    concurrencies: list[int],
    queries_per_worker: int,
    cached_queries_per_worker: int,
    buckets: int,
    include_counts: bool,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "runtime": get_python_runtime_status(),
        "system": {
            "platform": platform.platform(),
            "logical_cpus": os.cpu_count(),
        },
        "parameters": {
            "group_counts": group_counts,
            "concurrencies": concurrencies,
            "queries_per_worker": queries_per_worker,
            "cached_queries_per_worker": cached_queries_per_worker,
            "search_buckets": buckets,
            "include_counts": include_counts,
        },
        "cases": [
            _benchmark_group_count(
                group_count,
                buckets=buckets,
                concurrencies=concurrencies,
                queries_per_worker=queries_per_worker,
                cached_queries_per_worker=cached_queries_per_worker,
                include_counts=include_counts,
            )
            for group_count in group_counts
        ],
    }


def _print_table(report: dict[str, Any]) -> None:
    runtime = report["runtime"]
    print(
        f"CPython {runtime['version']} | free-threading="
        f"{runtime['free_threading_active']} | CPUs={report['system']['logical_cpus']}"
    )
    print(
        "groups  users  cold q/s  cold p50 ms  cold p95 ms  "
        "cached p95 ms"
    )
    for case in report["cases"]:
        for result in case["results"]:
            print(
                f"{case['groups']:>6}  {result['concurrency']:>5}  "
                f"{result['cold']['throughput_qps']:>8.1f}  "
                f"{result['cold']['latency_ms']['p50']:>11.2f}  "
                f"{result['cold']['latency_ms']['p95']:>11.2f}  "
                f"{result['cached']['latency_ms']['p95']:>13.3f}"
            )
        index = case["index"]
        print(
            f"        index: {index['build_seconds']:.3f}s, "
            f"{index['retained_python_mib']:.1f} MiB retained Python allocations"
        )


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be at least 1")
    return parsed


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--groups",
        type=_positive_int,
        nargs="+",
        default=[1_000, 5_000, 10_000, 20_000],
    )
    parser.add_argument(
        "--concurrency",
        type=_positive_int,
        nargs="+",
        default=[1, 4, 8, 16],
    )
    parser.add_argument("--queries-per-worker", type=_positive_int, default=4)
    parser.add_argument(
        "--cached-queries-per-worker",
        type=_positive_int,
        default=100,
    )
    parser.add_argument("--search-buckets", type=_positive_int, default=32)
    parser.add_argument(
        "--no-counts",
        action="store_true",
        help="Omit filtered facets, matching follow-up page requests.",
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    report = run_benchmark(
        group_counts=args.groups,
        concurrencies=args.concurrency,
        queries_per_worker=args.queries_per_worker,
        cached_queries_per_worker=args.cached_queries_per_worker,
        buckets=args.search_buckets,
        include_counts=not args.no_counts,
    )
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        _print_table(report)


if __name__ == "__main__":
    main()
