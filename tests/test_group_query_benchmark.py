from scripts.benchmark_group_queries import (
    SCHEMA_VERSION,
    build_synthetic_groups,
    run_benchmark,
)


def test_synthetic_groups_are_deterministic_and_queryable():
    first = build_synthetic_groups(5, buckets=2)
    second = build_synthetic_groups(5, buckets=2)

    assert first == second
    assert first[0]["title"].startswith("Synthetic finding search-bucket-0")
    assert first[1]["title"].startswith("Synthetic finding search-bucket-1")


def test_benchmark_report_contains_cold_and_cached_concurrency_results():
    report = run_benchmark(
        group_counts=[100],
        concurrencies=[1, 2],
        queries_per_worker=1,
        cached_queries_per_worker=2,
        buckets=4,
        include_counts=True,
    )

    assert report["schema_version"] == SCHEMA_VERSION
    assert report["runtime"]["implementation"] == "CPython"
    assert report["parameters"]["include_counts"] is True
    assert report["cases"][0]["groups"] == 100
    assert [
        result["concurrency"] for result in report["cases"][0]["results"]
    ] == [1, 2]
    for result in report["cases"][0]["results"]:
        assert result["cold"]["throughput_qps"] > 0
        assert result["cold"]["latency_ms"]["p95"] >= 0
        assert result["cached"]["throughput_qps"] > 0
