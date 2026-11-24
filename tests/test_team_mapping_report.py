"""The team mapping report (dtvp.team_mapping_report): what falls to ``*``,
under which project roots and top-level components, findings per entry,
the inventory, and the background service with its cache."""

import asyncio

import pytest

from dtvp.team_mapping_report import (
    FLAG_ROOT,
    FLAG_TOP_LEVEL,
    TeamMappingReportService,
    active_versions,
    build_mapping_report,
    purl_base,
)


def _bom(root, root_purl, components, edges):
    meta = {"bom-ref": "root", "name": root}
    if root_purl:
        meta["purl"] = root_purl
    return {
        "metadata": {"component": meta},
        "components": [
            {"bom-ref": ref, **fields} for ref, fields in components
        ],
        "dependencies": [{"ref": ref, "dependsOn": deps} for ref, deps in edges],
    }


# ViewPoint_Product: root -> core -> zlib; root -> libtiff; root -> app -> openssl
VP = _bom(
    "ViewPoint_Product",
    None,
    [
        ("core", {"name": "core"}),
        ("zlib", {"name": "zlib", "purl": "pkg:generic/zlib@1.3"}),
        ("tiff", {"name": "libtiff", "purl": "pkg:generic/libtiff@4.0"}),
        ("app", {"name": "app", "group": "com.vp"}),
        ("ssl", {"name": "OpenSSL", "purl": "pkg:generic/openssl@3.0"}),
    ],
    [("root", ["core", "tiff", "app"]), ("core", ["zlib"]), ("app", ["ssl"])],
)
# eventserver: a standalone project whose root has no purl.
EVENTS = _bom(
    "eventserver",
    None,
    [("lib", {"name": "netty", "group": "io.netty", "purl": "pkg:maven/io.netty/netty-codec@4.1"})],
    [("root", ["lib"])],
)
# stats-app: the root's purl names a package called differently.
STATS = _bom(
    "stats-app",
    "pkg:npm/vp-stats-app@0.1.2",
    [("tar", {"name": "tar", "purl": "pkg:npm/tar@2.2.2"})],
    [("root", ["tar"])],
)

BOMS = {"vp1": VP, "vp2": VP, "ev1": EVENTS, "st1": STATS}
FINDINGS = {
    "vp1": [
        {"uuid": "zlib", "name": "zlib", "purl": "pkg:generic/zlib@1.3"},
        {"uuid": "tiff", "name": "libtiff", "purl": "pkg:generic/libtiff@4.0"},
        {"uuid": "ssl", "name": "OpenSSL", "purl": "pkg:generic/openssl@3.0"},
    ],
    "vp2": [{"uuid": "zlib", "name": "zlib", "purl": "pkg:generic/zlib@1.3"}],
    "ev1": [
        {"uuid": "lib", "name": "netty", "purl": "pkg:maven/io.netty/netty-codec@4.1"},
        {"uuid": "lib", "name": "netty", "purl": "pkg:maven/io.netty/netty-codec@4.1"},
    ],
    "st1": [{"uuid": "tar", "name": "tar", "purl": "pkg:npm/tar@2.2.2"}],
}
VERSIONS = [
    {"project_uuid": "vp1", "project": "ViewPoint_Product", "version": "1.0"},
    {"project_uuid": "vp2", "project": "ViewPoint_Product", "version": "2.0"},
    {"project_uuid": "ev1", "project": "eventserver", "version": "5"},
    {"project_uuid": "st1", "project": "stats-app", "version": "0.1.2"},
]
MAPPING = {"com.vp:app": "Apps", "*": "Unknown"}


def report(mapping=MAPPING, versions=VERSIONS, **kwargs):
    return build_mapping_report(
        mapping, versions, BOMS.get, FINDINGS.get, **kwargs
    )


def rows_by_name(result):
    return {(row["kind"], row["name"]): row for row in result["unmapped"]}


def test_totals_and_per_project_counts():
    result = report()
    assert result["totals"] == {
        "versions": 4,
        "projects": 3,
        "findings": 7,
        "owned_by_component": 1,
        "owned_by_project": 0,
        "unmapped": 6,
    }
    projects = {project["name"]: project for project in result["projects"]}
    assert projects["ViewPoint_Product"]["findings"] == 4
    assert projects["ViewPoint_Product"]["unmapped"] == 3
    assert [v["version"] for v in projects["ViewPoint_Product"]["versions"]] == ["1.0", "2.0"]
    assert projects["eventserver"]["unmapped"] == 2


def test_findings_per_entry():
    result = report()
    assert result["entries"]["com.vp:app"] == {
        "findings": 1,
        "projects": [{"name": "ViewPoint_Product", "findings": 1}],
    }
    assert result["entries"]["*"]["findings"] == 6


def test_unmapped_roots_and_top_level_components_with_suggestions():
    rows = rows_by_name(report())
    root = rows[("root", "ViewPoint_Product")]
    assert root["findings"] == 3
    assert root["suggested_key"] == "project::ViewPoint_Product"
    assert root["projects"] == [
        {"name": "ViewPoint_Product", "findings": 3, "versions": ["1.0", "2.0"]}
    ]

    # zlib sits under the generic, purl-less "core": the row is "core",
    # scoped to the project.
    core = rows[("component", "core")]
    assert core["findings"] == 2
    assert core["suggested_key"] == "project:ViewPoint_Product::core"
    assert ("component", "zlib") not in rows

    # Directly under the root with a purl: its package name.
    tiff = rows[("component", "libtiff")]
    assert tiff["purl"] == "pkg:generic/libtiff"
    assert tiff["suggested_key"] == "libtiff"

    # A namespaced package: namespace:name.
    netty = rows[("component", "netty")]
    assert netty["findings"] == 2
    assert netty["suggested_key"] == "io.netty:netty-codec"

    # OpenSSL is owned through com.vp:app: not listed.
    assert ("component", "OpenSSL") not in rows
    assert rows[("root", "eventserver")]["suggested_key"] == "project::eventserver"


def test_a_project_fallback_takes_its_findings_off_the_list():
    mapping = {**MAPPING, "project::eventserver": "Events"}
    result = report(mapping)
    rows = rows_by_name(result)
    assert ("root", "eventserver") not in rows
    assert ("component", "netty") not in rows
    assert result["entries"]["project::eventserver"]["findings"] == 2
    assert result["totals"]["owned_by_project"] == 2
    projects = {project["name"]: project for project in result["projects"]}
    assert projects["eventserver"]["fallback_key"] == "project::eventserver"


def test_the_purl_fallback_and_project_scope_apply_in_the_report():
    mapping = {
        **MAPPING,
        "vp-stats-app": "Stats",
        "project:ViewPoint_Product::core": "VP Core",
    }
    result = report(mapping)
    rows = rows_by_name(result)
    assert ("root", "stats-app") not in rows
    assert ("component", "core") not in rows
    assert result["entries"]["vp-stats-app"]["findings"] == 1
    assert result["entries"]["project:ViewPoint_Product::core"]["findings"] == 2


def test_inventory_lists_components_with_findings_below_them():
    result = report()
    inventory = result["inventory"]
    assert inventory["projects"] == ["eventserver", "stats-app", "ViewPoint_Product"]
    vp = inventory["projects"].index("ViewPoint_Product")
    by_name = {item[0]: item for item in inventory["components"]}
    # core: two zlib findings (one per version) below it, both unmapped.
    assert by_name["core"][3] == [[vp, 2, 2, FLAG_TOP_LEVEL]]
    assert by_name["zlib"][2] == "pkg:generic/zlib"
    root = by_name["ViewPoint_Product"]
    assert root[3] == [[vp, 4, 3, FLAG_ROOT]]
    assert inventory["truncated"] is False
    assert inventory["total"] == len(inventory["components"])


def test_inventory_and_list_are_cut_at_their_limits():
    result = report(inventory_limit=2, unmapped_limit=1)
    assert len(result["inventory"]["components"]) == 2
    assert result["inventory"]["truncated"] is True
    assert len(result["unmapped"]) == 1
    assert result["unmapped_total"] > 1


def test_versions_without_stored_data_are_named():
    versions = VERSIONS + [{"project_uuid": "nope", "project": "Ghost", "version": "1"}]
    result = report(versions=versions)
    assert result["missing_versions"] == [
        {"project_uuid": "nope", "project": "Ghost", "version": "1"}
    ]


def test_a_finding_whose_component_is_not_in_the_bom_is_its_own_row():
    findings = {"x1": [{"uuid": "gone", "name": "mystery", "purl": None}]}
    result = build_mapping_report(
        MAPPING,
        [{"project_uuid": "x1", "project": "X", "version": "1"}],
        {"x1": EVENTS}.get,
        findings.get,
    )
    row = rows_by_name(result)[("component", "mystery")]
    assert row["in_bom"] is False
    assert row["suggested_key"] == "project:X::mystery"


def test_purl_base():
    assert purl_base("pkg:npm/%40s/x@1.0?a=b#c") == "pkg:npm/%40s/x"
    assert purl_base("pkg:generic/zlib") == "pkg:generic/zlib"
    assert purl_base(None) == ""


def test_active_versions_use_the_sync_state():
    class SyncState:
        def list_versions(self):
            return [
                {"project_uuid": "a", "product_name": "A", "version": "1", "active_in_dt": True, "status": "synced"},
                {"project_uuid": "b", "product_name": "A", "version": "0", "active_in_dt": False, "status": "synced"},
                {"project_uuid": "c", "product_name": "C", "version": "1", "active_in_dt": True, "status": "gone"},
            ]

    class Cache:
        sync_state = SyncState()

    assert active_versions(Cache()) == [{"project_uuid": "a", "project": "A", "version": "1"}]

    class EmptySync:
        def list_versions(self):
            return []

    class Fallback:
        sync_state = EmptySync()

        def get_cached_project_versions(self):
            return [{"uuid": "z", "name": "Z", "version": "9"}]

    assert active_versions(Fallback()) == [{"project_uuid": "z", "project": "Z", "version": "9"}]


# -- the service ----------------------------------------------------------


class Inputs:
    def __init__(self):
        self.mapping = dict(MAPPING)
        self.stamp = "t1"
        self.builds = 0

    def load_findings(self, uuid):
        return FINDINGS.get(uuid)

    def load_bom(self, uuid):
        self.builds += uuid == "vp1"
        return BOMS.get(uuid)


def make_service(inputs, **kwargs):
    return TeamMappingReportService(
        load_team_mapping=lambda: inputs.mapping,
        list_versions=lambda: list(VERSIONS),
        source_fingerprint=lambda versions: inputs.stamp,
        load_bom=inputs.load_bom,
        load_findings=inputs.load_findings,
        **kwargs,
    )


async def _settle(service):
    for _ in range(50):
        if service._task is None or service._task.done():
            return
        await asyncio.sleep(0.01)


def test_the_service_builds_in_the_background_and_caches():
    async def run():
        inputs = Inputs()
        service = make_service(inputs)
        first = await service.current()
        assert first["status"] == "building"
        assert first["report"] is None
        await _settle(service)
        ready = await service.current()
        assert ready["status"] == "ready"
        assert ready["stale"] is False
        assert ready["report"]["totals"]["findings"] == 7
        assert inputs.builds == 1

        # Unchanged inputs: the cached report, no new build.
        assert (await service.current())["status"] == "ready"
        assert inputs.builds == 1

        # A mapping change: the last report, stale, while the new one builds.
        inputs.mapping = {**MAPPING, "project::eventserver": "Events"}
        stale = await service.current()
        assert stale["status"] == "building"
        assert stale["stale"] is True
        assert stale["report"]["totals"]["owned_by_project"] == 0
        await _settle(service)
        fresh = await service.current()
        assert fresh["status"] == "ready"
        assert fresh["report"]["totals"]["owned_by_project"] == 2
        # The stored data did not change: the versions were not read again.
        assert inputs.builds == 1

        # Stored data changed: built again.
        inputs.stamp = "t2"
        assert (await service.current())["status"] == "building"
        await _settle(service)
        assert inputs.builds == 2

        # A forced rebuild reads everything again.
        assert (await service.current(refresh=True))["status"] == "building"
        await _settle(service)
        assert inputs.builds == 3

    asyncio.run(run())


def test_a_failed_build_is_reported_and_not_retried_for_the_same_inputs():
    async def run():
        inputs = Inputs()
        calls = {"n": 0}

        def broken(uuid):
            calls["n"] += 1
            raise RuntimeError("store unavailable")

        service = TeamMappingReportService(
            load_team_mapping=lambda: inputs.mapping,
            list_versions=lambda: list(VERSIONS),
            source_fingerprint=lambda versions: inputs.stamp,
            load_bom=broken,
            load_findings=inputs.load_findings,
        )
        await service.current()
        await _settle(service)
        failed = await service.current()
        assert failed["status"] == "failed"
        assert failed["error"] == "store unavailable"
        attempts = calls["n"]
        await service.current()
        assert calls["n"] == attempts
        await service.current(refresh=True)
        await _settle(service)
        assert calls["n"] > attempts

    asyncio.run(run())


# -- the endpoint ---------------------------------------------------------


@pytest.fixture
def report_route():
    from dtvp import main

    calls = []

    async def fake_report(*, refresh=False):
        calls.append(refresh)
        return {"status": "ready", "stale": False, "built_at": "now", "error": None, "report": {"totals": {}}}

    original = main.mapping_report_service.current
    main.mapping_report_service.current = fake_report
    yield main, calls
    main.mapping_report_service.current = original
    main.app.dependency_overrides = {}


def test_everyone_reads_the_report_and_only_reviewers_rebuild(client, report_route, monkeypatch):
    main, calls = report_route
    main.app.dependency_overrides[main.get_current_user] = lambda: "analyst"
    monkeypatch.setattr("dtvp.main.get_user_role", lambda user: "ANALYST")
    response = client.get("/api/settings/mapping/report")
    assert response.status_code == 200
    assert response.json()["status"] == "ready"
    assert client.get("/api/settings/mapping/report?refresh=true").status_code == 403

    monkeypatch.setattr("dtvp.main.get_user_role", lambda user: "REVIEWER")
    assert client.get("/api/settings/mapping/report?refresh=true").status_code == 200
    assert calls == [False, True]


# -- near duplicates, the tree and the preview ---------------------------

from dtvp.team_mapping_report import (  # noqa: E402
    VersionModel,
    near_duplicate_disagreements,
    preview_mapping_change,
    slim_bom,
    version_tree,
)


def test_near_duplicates_that_disagree_are_flagged():
    mapping = {
        "VPStatsApp": "Phoenix",
        "vp-stats-app": "Core",
        "purl::pkg:npm/vp-stats-app": "Core",
        "project:P::vp_stats_app": "Other",
        "libtiff": "3P",
        "LibTIFF": "3P",
    }
    assert near_duplicate_disagreements(mapping) == [
        {
            "token": "vpstatsapp",
            "teams": ["Core", "Phoenix"],
            "entries": [
                {"key": "VPStatsApp", "team": "Phoenix"},
                {"key": "purl::pkg:npm/vp-stats-app", "team": "Core"},
                {"key": "vp-stats-app", "team": "Core"},
            ],
        }
    ]
    assert report({**MAPPING, "Core": "A", "core": "B"})["near_duplicates"][0]["teams"] == ["A", "B"]


def model(uuid):
    version = next(item for item in VERSIONS if item["project_uuid"] == uuid)
    return VersionModel(
        project_uuid=uuid,
        project=version["project"],
        version=version["version"],
        stamp="",
        bom=slim_bom(BOMS[uuid]),
        findings=FINDINGS[uuid],
    )


def test_slim_bom_keeps_what_ownership_needs():
    bom = {
        "metadata": {"component": {"bom-ref": "r", "name": "R", "licenses": [1]}},
        "components": [{"bom-ref": "a", "name": "a", "hashes": [1], "purl": "pkg:x/a@1"}],
        "dependencies": [{"ref": "r", "dependsOn": ["a"]}],
    }
    assert slim_bom(bom) == {
        "metadata": {"component": {"bom-ref": "r", "name": "R"}},
        "components": [{"bom-ref": "a", "name": "a", "purl": "pkg:x/a@1"}],
        "dependencies": [{"ref": "r", "dependsOn": ["a"]}],
    }
    assert slim_bom(None) == {}


def test_the_tree_shows_owners_and_counts_one_level_at_a_time():
    mapping = {"com.vp:app": "Apps", "zlib": "Compression", "*": "Unknown"}
    top = version_tree(model("vp1"), mapping)
    assert top["root"]["name"] == "ViewPoint_Product"
    assert top["root"]["findings"] == 3
    assert top["root"]["unowned"] == 1
    assert top["root"]["owner"] == {"team": "Unknown", "kind": "wildcard", "key": "*"}

    level = version_tree(model("vp1"), mapping, "root")
    names = [node["name"] for node in level["nodes"]]
    # Unowned findings first.
    assert names == ["libtiff", "app", "core"]
    nodes = {node["name"]: node for node in level["nodes"]}
    assert nodes["app"]["owner"] == {"team": "Apps", "kind": "component", "key": "com.vp:app"}
    assert nodes["app"]["children"] == 1
    assert nodes["core"]["findings"] == 1 and nodes["core"]["unowned"] == 0

    below = version_tree(model("vp1"), mapping, "app")["nodes"]
    assert below[0]["name"] == "OpenSSL"
    assert below[0]["owner"]["kind"] == "inherited"
    assert below[0]["owner"]["from"] == ["app"]
    assert below[0]["findings_here"] == 1

    with pytest.raises(KeyError):
        version_tree(model("vp1"), mapping, "nope")


def test_the_tree_of_a_draft_names_the_saved_owner_where_it_changes():
    saved = {"com.vp:app": "Apps", "zlib": "Compression", "*": "Unknown"}
    draft = {**saved, "project:ViewPoint_Product::libtiff": "3P"}
    level = version_tree(model("vp1"), saved, "root", draft=draft)
    nodes = {node["name"]: node for node in level["nodes"]}
    assert nodes["libtiff"]["owner"] == {
        "team": "3P", "kind": "component", "key": "project:ViewPoint_Product::libtiff",
    }
    assert nodes["libtiff"]["unowned"] == 0
    assert nodes["libtiff"]["saved_owner"] == {"team": "Unknown", "kind": "wildcard", "key": "*"}
    # Unchanged owners carry no saved owner.
    assert "saved_owner" not in nodes["app"]
    assert "saved_owner" not in version_tree(model("vp1"), saved, "root")["nodes"][0]
    # The root's counts follow the draft.
    assert version_tree(model("vp1"), saved, draft=draft)["root"]["unowned"] == 0


def test_the_tree_of_a_flat_bom_lists_unlinked_components_under_the_root():
    flat = {
        "metadata": {"component": {"bom-ref": "root", "name": "flat"}},
        "components": [{"bom-ref": "a", "name": "a"}, {"bom-ref": "b", "name": "b"}],
    }
    item = VersionModel("f1", "flat", "1", "", flat, [{"uuid": "a", "name": "a"}])
    tree = version_tree(item, {"project::flat": "Flat"})
    assert tree["root"]["children"] == 2
    assert tree["root"]["owner"] == {"team": "Flat", "kind": "project", "key": "project::flat"}
    level = version_tree(item, {"project::flat": "Flat"}, "root")
    assert [(node["name"], node["unlinked"]) for node in level["nodes"]] == [("a", True), ("b", True)]


def test_the_preview_counts_findings_that_change_owner():
    models = [model(uuid) for uuid in ("vp1", "vp2", "ev1", "st1")]
    draft = {**MAPPING, "project::eventserver": "Events", "project:ViewPoint_Product::core": "VP Core"}
    result = preview_mapping_change(MAPPING, draft, models)
    assert result["findings"] == 7
    assert result["changed"] == 4
    assert result["moves"] == [
        {"from": "Unknown", "to": "Events", "findings": 2},
        {"from": "Unknown", "to": "VP Core", "findings": 2},
    ]
    assert result["projects"] == [
        {"name": "ViewPoint_Product", "changed": 2},
        {"name": "eventserver", "changed": 2},
    ]
    assert preview_mapping_change(MAPPING, MAPPING, models)["changed"] == 0


def test_the_service_serves_tree_and_preview():
    async def run():
        inputs = Inputs()
        service = make_service(inputs)
        tree = await service.tree("vp1", "root")
        assert tree["project"] == "ViewPoint_Product"
        assert inputs.builds == 1
        await service.tree("vp1")
        assert inputs.builds == 1  # the model is kept
        with pytest.raises(LookupError):
            await service.tree("nope")
        drafted = await service.tree("vp1", "root", {**MAPPING, "project::ViewPoint_Product": "VP"})
        assert any("saved_owner" in node for node in drafted["nodes"])
        preview = await service.preview(
            {**MAPPING, "project::eventserver": "Events"}, ["EventServer"]
        )
        assert preview["changed"] == 2
        assert preview["findings"] == 2

    asyncio.run(run())


def test_tree_and_preview_routes(client, monkeypatch):
    from dtvp import main

    async def fake_tree(project_uuid, ref, draft=None):
        if project_uuid == "missing":
            raise LookupError(project_uuid)
        result = {"project_uuid": project_uuid, "ref": ref}
        if draft is not None:
            result["draft"] = draft
        return result

    seen = {}

    async def fake_preview(mapping, projects):
        seen["args"] = (mapping, projects)
        return {"changed": 1}

    monkeypatch.setattr(main.mapping_report_service, "tree", fake_tree)
    monkeypatch.setattr(main.mapping_report_service, "preview", fake_preview)
    main.app.dependency_overrides[main.get_current_user] = lambda: "someone"
    try:
        monkeypatch.setattr("dtvp.main.get_user_role", lambda user: "ANALYST")
        assert client.get("/api/settings/mapping/tree?project_uuid=v1&ref=a").json() == {
            "project_uuid": "v1",
            "ref": "a",
        }
        assert client.get("/api/settings/mapping/tree?project_uuid=missing").status_code == 404
        body = {"mapping": {"Core": {"projects": ["P"]}}}
        assert client.post("/api/settings/mapping/preview", json=body).status_code == 403
        draft_body = {"project_uuid": "v1", "ref": "a", **body}
        assert client.post("/api/settings/mapping/tree", json=draft_body).status_code == 403
        monkeypatch.setattr("dtvp.main.get_user_role", lambda user: "REVIEWER")
        assert client.post("/api/settings/mapping/preview", json=body).json() == {"changed": 1}
        # The team format reaches the engine as selectors.
        assert seen["args"] == ({"project::P": "Core"}, None)
        assert client.post("/api/settings/mapping/preview", json={"mapping": []}).status_code == 422
        # The tree of a draft: the draft reaches the engine as selectors.
        assert client.post("/api/settings/mapping/tree", json=draft_body).json() == {
            "project_uuid": "v1",
            "ref": "a",
            "draft": {"project::P": "Core"},
        }
        assert client.post(
            "/api/settings/mapping/tree", json={**draft_body, "project_uuid": "missing"}
        ).status_code == 404
        for broken in ({"mapping": []}, {"project_uuid": ""}, {"project_uuid": 3}, {"ref": 1}):
            assert client.post(
                "/api/settings/mapping/tree", json={**draft_body, **broken}
            ).status_code == 422
    finally:
        main.app.dependency_overrides = {}
