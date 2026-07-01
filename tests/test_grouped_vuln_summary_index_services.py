from pathlib import Path

from dtvp.grouped_vuln_summary_index_services import (
    GroupedVulnSummaryIndex,
    build_grouped_vuln_summary_cache_key,
    get_grouped_vuln_summary_index_path,
)


def test_grouped_vuln_summary_index_round_trips_entry(tmp_path):
    index_path = tmp_path / "summary.sqlite"
    index = GroupedVulnSummaryIndex(
        path_provider=lambda: str(index_path),
        max_entries_provider=lambda: 4,
    )
    key = build_grouped_vuln_summary_cache_key(
        name="App",
        cve=None,
        versions=[{"uuid": "u1", "name": "App", "version": "1.0.0"}],
        team_mapping={"*": "Team"},
        cache_revision="rev-1",
    )

    index.save(
        key,
        scope={"name": "App"},
        summaries=[{"id": "CVE-1", "affected_versions": []}],
        statistics_rollup={"version_counts": {"1.0.0": 1}},
        total_versions=1,
    )

    loaded = index.load(key)

    assert loaded is not None
    assert loaded["result"][0]["id"] == "CVE-1"
    assert loaded["statistics_rollup"]["version_counts"] == {"1.0.0": 1}
    assert loaded["total_versions"] == 1


def test_grouped_vuln_summary_cache_key_tracks_team_and_cache_revision():
    base = {
        "name": "App",
        "cve": "CVE-1",
        "versions": [{"uuid": "u1", "name": "App", "version": "1.0.0"}],
    }

    first = build_grouped_vuln_summary_cache_key(
        **base,
        team_mapping={"*": "TeamA"},
        cache_revision="rev-1",
    )
    changed_team = build_grouped_vuln_summary_cache_key(
        **base,
        team_mapping={"*": "TeamB"},
        cache_revision="rev-1",
    )
    changed_revision = build_grouped_vuln_summary_cache_key(
        **base,
        team_mapping={"*": "TeamA"},
        cache_revision="rev-2",
    )

    assert first != changed_team
    assert first != changed_revision


def test_grouped_vuln_summary_index_default_sits_next_to_dt_cache(monkeypatch):
    monkeypatch.setenv("DTVP_DT_CACHE_PATH", "/tmp/dtvp-cache/dt_cache")

    assert get_grouped_vuln_summary_index_path() == str(
        Path("/tmp/dtvp-cache/grouped_vuln_summary_index.sqlite")
    )
