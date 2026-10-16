"""Complete synthetic catalog archives exercise capture, search and reconstruction."""

import gzip
import io
import sqlite3
import tarfile

import pytest

from dtvp.knowledge.cpe_catalog import Catalog, parse_meta
from dtvp.storage import Artifacts, canonical, digest


def product(number, *, deprecated=False):
    return {
        "cpe": {
            "cpeName": f"cpe:2.3:a:example:catalog_demo:{number}:*:*:*:*:*:*:*",
            "cpeNameId": f"cpe-id-{number}",
            "deprecated": deprecated,
            "titles": [{"title": f"Catalog demo release {number}", "lang": "en"}],
            "refs": [{"ref": "https://example.invalid/source"}],
            "unknown_source_extension": {"retained": number},
        }
    }


def archive(tmp_path, groups=None, *, total=None, base=1, mutate=None, extra=None):
    groups = groups if groups is not None else [[product(1)], [product(2, deprecated=True)]]
    total = sum(len(group) for group in groups) if total is None else total
    stream = io.BytesIO()
    ordinal = base
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for i, group in enumerate(groups):
            document = {
                "format": "NVD_CPE",
                "version": "2.0",
                "timestamp": "2099-01-01T00:00:00",
                "startIndex": ordinal,
                "totalResults": total,
                "resultsPerPage": len(group),
                "products": group,
            }
            raw = canonical(document)
            if mutate:
                raw = mutate(i, raw)
            info = tarfile.TarInfo(f"nvdcpe-2.0-chunks/chunk-{i:05}.json")
            info.size = len(raw)
            tar.addfile(info, io.BytesIO(raw))
            ordinal += len(group)
        if extra:
            extra(tar)
    raw = stream.getvalue()
    compressed = gzip.compress(raw, mtime=0)
    target = tmp_path / "source.tar.gz"
    meta = tmp_path / "source.meta"
    target.write_bytes(compressed)
    meta.write_bytes(
        f"lastModifiedDate:2099-01-01T00:00:00Z\r\nsize:{len(raw)}\r\ngzSize:{len(compressed)}\r\nsha256:{digest(raw)}\r\n".encode()
    )
    return target, meta


def test_complete_catalog_capture_search_deprecated_history_and_rebuild(tmp_path, monkeypatch):
    monkeypatch.setattr("dtvp.knowledge.cpe_catalog.CHUNK_BYTES", 128)
    catalog = Catalog(tmp_path / "catalog")
    source, meta = archive(tmp_path)
    original = source.read_bytes()
    result = catalog.import_archive(source, meta)
    generation = result["generation"]
    assert catalog.current() == generation and result["records"] == 2
    assert result["assurance"] == "META_consistent_complete_archive"
    objects = Artifacts(catalog.root / "objects")
    assert b"".join(objects.read(chunk["sha256"]) for chunk in result["chunks"]) == original
    assert objects.read(result["meta_sha256"]) == meta.read_bytes()
    page = catalog.search("catalog demo")
    assert page["generation"] == generation and page["total"] == 1
    assert page["items"][0]["record"]["cpe"]["unknown_source_extension"] == {"retained": 1}
    all_rows = catalog.search("catalog", include_deprecated=True, limit=1)
    assert all_rows["total"] == 2 and all_rows["next_offset"] == 1
    assert catalog.search("catalog", include_deprecated=True, offset=1)["items"][0]["record"][
        "cpe"
    ]["deprecated"]
    assert catalog.verify()["verified"]
    index = catalog.root / "indexes" / (generation + ".sqlite")
    index.unlink()
    with pytest.raises(ValueError, match="index"):
        catalog.search("catalog")
    assert catalog.verify(rebuild=True)["index_rebuilt"]
    assert catalog.search("catalog")["total"] == 1
    source, meta = archive(tmp_path, [[product(3)]], base=0)
    replacement = catalog.import_archive(source, meta)
    assert replacement["generation"] != generation
    assert catalog.search("catalog", generation=generation)["total"] == 1
    assert catalog.current() == replacement["generation"]


def test_catalog_exceeds_curated_source_limit_without_copying_project_state(tmp_path):
    catalog = Catalog(tmp_path / "catalog")
    groups = [[product(i) for i in range(1001)], [product(i) for i in range(1001, 2003)]]
    source, meta = archive(tmp_path, groups)
    captured = catalog.import_archive(source, meta)
    assert captured["records"] == 2003
    page = catalog.search("catalog", offset=2000, limit=10)
    assert page["total"] == 2003 and len(page["items"]) == 3 and page["next_offset"] is None
    assert not (tmp_path / "knowledge").exists()


@pytest.mark.parametrize(
    "case",
    [
        "missing-page",
        "overlap",
        "duplicate-name",
        "duplicate-key",
        "malformed-json",
        "bad-hash",
        "bad-size",
        "truncated",
        "wrong-format",
    ],
)
def test_invalid_capture_keeps_previous_generation_selected(tmp_path, case):
    catalog = Catalog(tmp_path / "catalog")
    source, meta = archive(tmp_path)
    prior = catalog.import_archive(source, meta)["generation"]
    if case == "missing-page":
        source, meta = archive(tmp_path, [[product(3)]], total=2)
    elif case == "overlap":
        source, meta = archive(
            tmp_path,
            mutate=lambda i, raw: raw.replace(b'"startIndex":2', b'"startIndex":1') if i else raw,
        )
    elif case == "duplicate-name":
        source, meta = archive(tmp_path, [[product(1)], [product(1)]])
    elif case == "duplicate-key":
        source, meta = archive(
            tmp_path,
            mutate=lambda _, raw: raw.replace(
                b'"version":"2.0"', b'"version":"2.0","version":"2.0"'
            ),
        )
    elif case == "malformed-json":
        source, meta = archive(tmp_path, mutate=lambda _, raw: raw[:-2])
    elif case == "wrong-format":
        source, meta = archive(tmp_path, mutate=lambda _, raw: raw.replace(b"NVD_CPE", b"OTHER"))
    elif case == "bad-hash":
        meta.write_text(meta.read_text().replace(parse_meta(meta.read_bytes())["sha256"], "0" * 64))
    elif case == "bad-size":
        meta.write_text(meta.read_text().replace("size:10240", "size:10241"))
    else:
        source.write_bytes(source.read_bytes()[:-20])
    with pytest.raises(ValueError):
        catalog.import_archive(source, meta)
    assert catalog.current() == prior
    assert catalog.search("catalog")["total"] == 1


@pytest.mark.parametrize(
    "kind", ["traversal", "absolute", "symlink", "hardlink", "other-file", "duplicate-member"]
)
def test_archive_is_never_extracted_and_rejects_unsafe_members(tmp_path, kind):
    def add(tar):
        name = {
            "traversal": "../outside.json",
            "absolute": "/outside.json",
            "other-file": "unrelated.bin",
            "duplicate-member": "nvdcpe-2.0-chunks/chunk-00000.json",
        }.get(kind, "link.json")
        info = tarfile.TarInfo(name)
        if kind in {"symlink", "hardlink"}:
            info.type = tarfile.SYMTYPE if kind == "symlink" else tarfile.LNKTYPE
            info.linkname = "/etc/passwd"
        tar.addfile(info)

    source, meta = archive(tmp_path, extra=add)
    catalog = Catalog(tmp_path / "catalog")
    with pytest.raises(ValueError, match="archive"):
        catalog.import_archive(source, meta)
    assert catalog.current() is None and not (tmp_path / "outside.json").exists()


def test_retained_chunk_corruption_and_modified_index_fail_closed(tmp_path):
    catalog = Catalog(tmp_path / "catalog")
    source, meta = archive(tmp_path)
    result = catalog.import_archive(source, meta)
    index = catalog.root / "indexes" / (result["generation"] + ".sqlite")
    with sqlite3.connect(index) as db:
        db.execute("UPDATE entries SET record='{}'")
    with pytest.raises(ValueError, match="receipt"):
        catalog.search("catalog")
    catalog.verify(rebuild=True)
    objects = Artifacts(catalog.root / "objects")
    objects.path(result["chunks"][0]["sha256"]).write_bytes(b"changed source")
    with pytest.raises(ValueError, match="integrity"):
        catalog.verify(rebuild=True)


@pytest.mark.parametrize("query", ["", "a", "x" * 201])
def test_query_bounds_and_uninitialized_reads_do_not_create_storage(tmp_path, query):
    catalog = Catalog(tmp_path / "absent")
    assert catalog.current() is None
    with pytest.raises(ValueError):
        catalog.search(query)
    assert not catalog.root.exists()


def test_literal_meta_line_separators_and_duplicate_fields(tmp_path):
    _, meta = archive(tmp_path)
    assert parse_meta(meta.read_bytes().replace(b"\r\n", b"\\r\\n"))["size"] == 10240
    with pytest.raises(ValueError, match="duplicate"):
        parse_meta(meta.read_bytes() + b"size:100\n")


def test_valid_sql_tampering_invalidates_cached_exact_index_proof(tmp_path):
    catalog = Catalog(tmp_path / "catalog")
    source, meta = archive(tmp_path)
    result = catalog.import_archive(source, meta)
    assert catalog.search("catalog")["total"] == 1
    index = catalog.root / "indexes" / (result["generation"] + ".sqlite")
    with sqlite3.connect(index) as db:
        before = db.execute("SELECT count(*) FROM entries").fetchone()[0]
        raw = db.execute("SELECT record FROM entries WHERE ordinal=1").fetchone()[0]
        changed = raw.replace("catalog_demo:1", "catalog_demo:9")
        db.execute(
            "UPDATE entries SET name=?,record=?,sha=? WHERE ordinal=1",
            ("cpe:2.3:a:example:catalog_demo:9:*:*:*:*:*:*:*", changed, digest(changed.encode())),
        )
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert db.execute("SELECT count(*) FROM entries").fetchone()[0] == before
    with pytest.raises(ValueError, match="receipt"):
        catalog.search("catalog")
    catalog.verify(rebuild=True)
    assert catalog.search("catalog")["items"][0]["record"]["cpe"]["cpeName"].endswith(
        ":1:*:*:*:*:*:*:*"
    )


def test_curated_export_is_explicit_bounded_page_and_originals_stay_retained(tmp_path):
    from dtvp.knowledge.cpe_sources import dictionary

    catalog = Catalog(tmp_path / "catalog")
    source, meta = archive(tmp_path)
    catalog.import_archive(source, meta)
    result = catalog.export("catalog", include_deprecated=True, limit=1)
    assert len(result["dictionary"]) == 1 and result["capture"]["total"] == 2
    assert result["capture"]["next_offset"] == 1
    assert "unknown_source_extension" in result["unprojected_record_fields"]
    raw = canonical(result["dictionary"])
    assert digest(raw) == result["artifact_sha256"]
    normalized, _ = dictionary(raw, "catalog")
    assert normalized[0]["source"] == "nvd-catalog:" + catalog.current()


def test_nonzero_archive_trailing_bytes_do_not_hide_unparsed_catalog_content(tmp_path):
    source, meta = archive(tmp_path)
    decoded = gzip.decompress(source.read_bytes()) + b"hidden unparsed content"
    compressed = gzip.compress(decoded, mtime=0)
    source.write_bytes(compressed)
    meta.write_text(
        f"lastModifiedDate:2099-01-01T00:00:00Z\nsize:{len(decoded)}\ngzSize:{len(compressed)}\nsha256:{digest(decoded)}\n"
    )
    catalog = Catalog(tmp_path / "catalog")
    with pytest.raises(ValueError, match="after catalog"):
        catalog.import_archive(source, meta)
    assert catalog.current() is None


def test_oversized_meta_and_unbounded_parser_tokens_keep_current_generation(tmp_path, monkeypatch):
    catalog = Catalog(tmp_path / "catalog")
    source, meta = archive(tmp_path)
    previous = catalog.import_archive(source, meta)["generation"]
    meta.write_bytes(b"x" * (64 * 1024 + 1))
    with pytest.raises(ValueError, match="META"):
        catalog.import_archive(source, meta)
    assert catalog.current() == previous
    source, meta = archive(
        tmp_path,
        mutate=lambda _, raw: raw.replace(
            b'"format":"NVD_CPE"', b'"giant":"' + b"x" * (512 * 1024) + b'","format":"NVD_CPE"'
        ),
    )
    monkeypatch.setattr("dtvp.knowledge.cpe_catalog.MAX_UNEMITTED_BYTES", 128 * 1024)
    with pytest.raises(ValueError, match="parser made no progress"):
        catalog.import_archive(source, meta)
    assert catalog.current() == previous


def test_excessive_unknown_root_keys_fail_before_selection(tmp_path):
    raw_fields = b",".join(b'"key' + str(i).encode() + b'":1' for i in range(10_001))
    source, meta = archive(
        tmp_path, mutate=lambda _, raw: b'{"unknown":{' + raw_fields + b"}," + raw[1:]
    )
    catalog = Catalog(tmp_path / "catalog")
    with pytest.raises(ValueError, match="object key bounds"):
        catalog.import_archive(source, meta)
    assert catalog.current() is None
