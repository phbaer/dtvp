"""Gone findings known only by component UUID get their component's name
from local sources, once."""

import os
from contextlib import closing

from dtvp import gone_component_names
from dtvp.bundle_io import sha256_hex, stable_json_bytes
from dtvp.finding_lifecycle_services import FindingLifecycleStore
from dtvp.gone_component_names import resolve_gone_component_names
from dtvp.project_archive_services import (
    ARCHIVE_FILE_SUFFIX,
    ARCHIVE_SCHEMA_VERSION,
    _write_zip_file,
)

import pytest

LIB = {"name": "lib-a", "version": "1.0", "purl": "pkg:npm/lib-a@1.0"}


@pytest.fixture(autouse=True)
def _forget_lookups():
    gone_component_names._attempted.clear()
    gone_component_names._archive_cache.clear()
    yield
    gone_component_names._attempted.clear()
    gone_component_names._archive_cache.clear()


def _store(tmp_path, *components):
    store = FindingLifecycleStore(str(tmp_path / "dtvp.sqlite3"))
    store._ensure_initialized()
    with closing(store._connect()) as connection, connection:
        for component_uuid in components:
            connection.execute(
                """
                INSERT INTO finding_presence (
                    project_uuid, component_uuid, vulnerability_uuid,
                    first_seen_at, status, gone_at, gone_reason
                ) VALUES ('p1', ?, 'v1', '2026-11-01', 'gone', '2026-11-02',
                          'component_removed')
                """,
                (component_uuid,),
            )
    store._presence.clear()
    return store


def _archive(directory, name, project_uuid, *, findings=(), bom=None):
    files = {
        "versions/0001-1.0/project.json": stable_json_bytes({"uuid": project_uuid}),
        "versions/0001-1.0/bom.json": stable_json_bytes(bom or {}),
        "versions/0001-1.0/findings.json": stable_json_bytes(list(findings)),
        "versions/0001-1.0/vulnerabilities.json": stable_json_bytes([]),
        "versions/0001-1.0/assessments.json": stable_json_bytes([]),
    }
    manifest = {
        "schema_version": ARCHIVE_SCHEMA_VERSION,
        "project": {
            "name": "App",
            "versions": [
                {
                    "project": {"uuid": project_uuid, "version": "1.0"},
                    "paths": {
                        kind: f"versions/0001-1.0/{kind}.json"
                        for kind in ("project", "bom", "findings", "vulnerabilities", "assessments")
                    },
                }
            ],
        },
        "files": {
            path: {"sha256": sha256_hex(data), "size": len(data)}
            for path, data in files.items()
        },
    }
    files["manifest.json"] = stable_json_bytes(manifest)
    path = os.path.join(directory, f"{name}{ARCHIVE_FILE_SUFFIX}")
    _write_zip_file(path, files)
    return path


def _row(store, component_uuid):
    return store.presence("p1")[(component_uuid, "v1")]


def test_names_come_from_the_stored_bom(tmp_path):
    store = _store(tmp_path, "c1")
    bom = {"components": [{"bom-ref": "c1", **LIB}]}

    filled = resolve_gone_component_names(
        store, "p1", stored_bom=lambda: bom, archive_dir=None
    )

    row = _row(store, "c1")
    assert filled == 1
    assert (row["component_name"], row["component_version"], row["component_purl"]) == (
        "lib-a", "1.0", "pkg:npm/lib-a@1.0",
    )
    assert row["component_identity"] == "pkg:npm/lib-a"


def test_names_come_from_archives_newest_first(tmp_path):
    store = _store(tmp_path, "c1", "c2")
    archives = tmp_path / "archives"
    archives.mkdir()
    older = _archive(
        archives, "older", "p1",
        findings=[{"component": {"uuid": "c1", "name": "old-name", "version": "0.9"}}],
    )
    os.utime(older, (1, 1))
    _archive(archives, "other-project", "p2", bom={"components": [{"bom-ref": "c2", **LIB}]})
    _archive(
        archives, "newer", "p1",
        findings=[{"component": {"uuid": "c1", **LIB}}],
        bom={"components": [{"bom-ref": "c2", "name": "lib-b", "version": "2.0"}]},
    )

    filled = resolve_gone_component_names(
        store, "p1", stored_bom=lambda: None, archive_dir=str(archives)
    )

    assert filled == 2
    assert (_row(store, "c1")["component_name"], _row(store, "c1")["component_version"]) == ("lib-a", "1.0")
    assert (_row(store, "c2")["component_name"], _row(store, "c2")["component_version"]) == ("lib-b", "2.0")


def test_the_lookup_is_done_once_and_unresolved_rows_keep_their_uuid(tmp_path):
    store = _store(tmp_path, "c1", "c-unknown")
    calls = []

    def stored_bom():
        calls.append(1)
        return {"components": [{"bom-ref": "c1", **LIB}]}

    first = resolve_gone_component_names(store, "p1", stored_bom=stored_bom, archive_dir=None)
    second = resolve_gone_component_names(store, "p1", stored_bom=stored_bom, archive_dir=None)

    assert (first, second, len(calls)) == (1, 0, 1)
    assert _row(store, "c-unknown")["component_name"] is None
    # A name already known is never overwritten.
    store.fill_components("p1", {"c1": {"component_name": "other"}})
    assert _row(store, "c1")["component_name"] == "lib-a"


def test_a_broken_archive_is_skipped(tmp_path):
    store = _store(tmp_path, "c1")
    archives = tmp_path / "archives"
    archives.mkdir()
    (archives / f"broken{ARCHIVE_FILE_SUFFIX}").write_bytes(b"not a zip")

    assert resolve_gone_component_names(
        store, "p1", stored_bom=lambda: None, archive_dir=str(archives)
    ) == 0
    assert _row(store, "c1")["component_name"] is None


def test_the_gone_findings_route_serves_the_resolved_name(tmp_path):
    """Checked through the store as the route uses it: the described row
    carries the name after the lookup."""
    from dtvp.finding_lifecycle_services import describe_gone_findings

    store = _store(tmp_path, "c1")
    resolve_gone_component_names(
        store, "p1",
        stored_bom=lambda: {"components": [{"bom-ref": "c1", **LIB}]},
        archive_dir=None,
    )

    class Outbox:
        def get_overlay(self, key):
            return None

    described = describe_gone_findings(store, Outbox(), "p1")
    [finding] = described["findings"]
    assert (finding["component_name"], finding["component_version"]) == ("lib-a", "1.0")


def test_an_archive_is_parsed_once_for_every_project_and_reads_are_bounded(tmp_path, monkeypatch):
    """After a restart every project version may ask: an archive is read
    once and kept for all of them, and one call reads at most
    ``max_archive_reads`` new archives; the next call goes on."""
    archives = tmp_path / "archives"
    archives.mkdir()
    for index in range(3):
        path = _archive(str(archives), f"a{index}", "p-other",
                        bom={"components": [{"bom-ref": "x", **LIB}]})
        os.utime(path, (1000 + index, 1000 + index))
    _archive(str(archives), "named", "p1", bom={"components": [{"bom-ref": "c1", **LIB}]})
    os.utime(os.path.join(str(archives), f"named{ARCHIVE_FILE_SUFFIX}"), (900, 900))
    reads = []
    real = gone_component_names.load_project_archive
    monkeypatch.setattr(
        gone_component_names, "load_project_archive",
        lambda path: reads.append(os.path.basename(path)) or real(path),
    )
    store = _store(tmp_path, "c1")

    first = resolve_gone_component_names(
        store, "p1", stored_bom=lambda: None, archive_dir=str(archives), max_archive_reads=2
    )
    assert (first, len(reads)) == (0, 2)  # budget spent, not given up
    second = resolve_gone_component_names(
        store, "p1", stored_bom=lambda: None, archive_dir=str(archives), max_archive_reads=2
    )
    assert second == 1 and _row(store, "c1")["component_name"] == "lib-a"
    assert len(reads) == 4  # the first two came from the cache

    other = _store(tmp_path / "other", "x")
    other_reads = len(reads)
    resolve_gone_component_names(
        other, "p1", stored_bom=lambda: None, archive_dir=str(archives), max_archive_reads=0
    )
    assert len(reads) == other_reads  # every archive already parsed
