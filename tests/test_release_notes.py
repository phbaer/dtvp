import json
import os

from fastapi import FastAPI
from fastapi.testclient import TestClient

from dtvp.app_info_routes import AppInfoRouteDeps, create_app_info_router
from dtvp.release_notes import (
    entry_from_message,
    load_releases,
    releases_from_context,
    releases_from_markdown,
)


def _commit(raw: str, **extra):
    return {"raw_message": raw, "message": raw, **extra}


def test_only_what_users_need_is_listed_and_reworded():
    [release] = releases_from_context([
        {
            "version": "v1.4.0",
            "timestamp": 1795329381,
            "commits": [
                _commit("feat(sync): show progress, cancel runs (#337)\n\nLong body."),
                _commit("fix: the export keeps the response. (#12)"),
                _commit("perf(grouped): parse each text once"),
                _commit("chore: release candidate 1.4.0 (#20)"),
                _commit("ci: pin the runner"),
                _commit("test(sync): wait with a deadline (#330)"),
                _commit("docs: the runtime page"),
                _commit("refactor(cache): store-only readers"),
                _commit("build: node 24"),
                _commit("style: format"),
                _commit("fix(deps): update dependency vue to v3.6 (#99)"),
                _commit("chore(deps): update node docker tag to v24 (#98)"),
                _commit("Merge pull request 'Update dependency x' (#97)"),
            ],
        }
    ])

    assert release["version"] == "1.4.0"
    assert release["date"] == "2026-11-22"
    assert release["prerelease"] is False
    assert release["unreleased"] is False
    groups = release["groups"]
    assert groups["breaking"] == []
    assert groups["new"] == [
        {"text": "Show progress, cancel runs", "scope": "sync", "pr": 337,
         "breaking": False, "note": None},
    ]
    assert groups["fixed"] == [
        {"text": "The export keeps the response", "scope": None, "pr": 12,
         "breaking": False, "note": None},
    ]
    assert [entry["text"] for entry in groups["faster"]] == ["Parse each text once"]


def test_breaking_changes_come_with_their_note():
    [release] = releases_from_context([
        {
            "version": "v2.0.0",
            "timestamp": 1795329381,
            "commits": [
                # "!" in the header; git-cliff repeats the description.
                _commit(
                    "feat(sync)!: no polling of watched products (#337)",
                    breaking=True,
                    breaking_description="no polling of watched products (#337)",
                ),
                # A footer, also on a type that is otherwise hidden.
                _commit(
                    "chore(config): drop a setting\n\n"
                    "BREAKING CHANGE: remove DTVP_SYNC_WATCHED_FINDINGS_SECONDS\n"
                    "from your environment.\n"
                ),
            ],
        }
    ])

    breaking = release["groups"]["breaking"]
    assert [entry["text"] for entry in breaking] == [
        "No polling of watched products",
        "Drop a setting",
    ]
    assert breaking[0]["note"] is None
    assert breaking[1]["note"] == (
        "remove DTVP_SYNC_WATCHED_FINDINGS_SECONDS from your environment."
    )
    assert release["groups"]["new"] == []


def test_a_subject_joined_with_its_body_ends_at_the_pr_number():
    group, entry = entry_from_message(
        "feat(gone-findings): flag risky losses (#327)The generator's eighth reading"
    )
    assert group == "new"
    assert entry["text"] == "Flag risky losses"
    assert entry["pr"] == 327


def test_prereleases_unreleased_and_duplicates():
    releases = releases_from_context([
        {"version": None, "timestamp": 0, "commits": [_commit("feat: a")]},
        {
            "version": "v2.0.0rc3",
            "timestamp": 1795329381,
            "commits": [_commit("fix: same (#1)"), _commit("fix: same (#2)")],
        },
    ])

    assert releases[0]["version"] is None
    assert releases[0]["unreleased"] is True
    assert releases[0]["date"] is None
    assert releases[1]["version"] == "2.0.0rc3"
    assert releases[1]["prerelease"] is True
    assert len(releases[1]["groups"]["fixed"]) == 1


MARKDOWN = """# Changelog

## [Unreleased]

### 🚀 Features
- **sync:** Show progress (#337)

## [2.0.0rc3] — 2026-11-22

### 🐛 Bug Fixes
- **cyclonedx:** Aliases from every finding (#326)
- Fix(lifecycle): name predating rows (#331)The joined body
- ⚠️ **BREAKING** **sync:** No polling (#338)

### 🔧 Maintenance
- Release candidate 2.0.0rc3 (#329)

### ⚡ Performance
- Parse each text once
"""


def test_markdown_fallback_reads_sections_scopes_and_breaking_marks():
    unreleased, rc3 = releases_from_markdown(MARKDOWN)

    assert unreleased["unreleased"] is True
    assert unreleased["groups"]["new"][0] == {
        "text": "Show progress", "scope": "sync", "pr": 337,
        "breaking": False, "note": None,
    }
    assert rc3["version"] == "2.0.0rc3"
    assert rc3["date"] == "2026-11-22"
    assert rc3["prerelease"] is True
    assert [(e["text"], e["scope"]) for e in rc3["groups"]["fixed"]] == [
        ("Aliases from every finding", "cyclonedx"),
        ("Name predating rows", "lifecycle"),
    ]
    assert [e["text"] for e in rc3["groups"]["breaking"]] == ["No polling"]
    assert [e["text"] for e in rc3["groups"]["faster"]] == ["Parse each text once"]
    assert all(
        "Release candidate" not in e["text"]
        for group in rc3["groups"].values() for e in group
    )


def test_load_prefers_the_context_falls_back_to_markdown_and_to_nothing(tmp_path):
    assert load_releases(str(tmp_path)) == []

    (tmp_path / "CHANGELOG.md").write_text(MARKDOWN, encoding="utf-8")
    assert [r["version"] for r in load_releases(str(tmp_path))] == [None, "2.0.0rc3"]

    context = tmp_path / "CHANGELOG.json"
    context.write_text("not json", encoding="utf-8")
    assert [r["version"] for r in load_releases(str(tmp_path))] == [None, "2.0.0rc3"]

    context.write_text(json.dumps([
        {"version": "v3.0.0", "timestamp": 1795329381, "commits": [_commit("feat: x")]},
    ]), encoding="utf-8")
    stat = context.stat()
    os.utime(context, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000_000))
    assert [r["version"] for r in load_releases(str(tmp_path))] == ["3.0.0"]


def test_the_changelog_route_returns_the_releases():
    app = FastAPI()
    releases = [{"version": "1.0.0", "groups": {}}]
    deps = AppInfoRouteDeps(
        version="1.0.0",
        build_commit="abc",
        load_pyproject_metadata=lambda: {},
        get_cache_status=lambda: {},
        load_changelog_content=lambda: "# Changelog",
        get_sbom_path=lambda _name: None,
        read_text=lambda _path: "",
        build_sbom_html=lambda content: content,
        backend_sbom_filename="b.json",
        frontend_sbom_filename="f.json",
        html_sbom_filename="h.json",
        media_type_json="application/json",
        load_release_notes=lambda: releases,
    )
    app.include_router(create_app_info_router(app, deps, not_found_response={}), prefix="/api")

    assert TestClient(app).get("/api/changelog").json() == {
        "content": "# Changelog",
        "releases": releases,
    }
