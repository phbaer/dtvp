"""CLI streams exact archive bytes; only the backend interprets legacy data."""

import json
import sys
from pathlib import Path

import httpx
import pytest
import respx

from dtvp.cli import main
from dtvp.knowledge.legacy_archive import MAX_COMPRESSED


def argv(monkeypatch, path, *extra):
    monkeypatch.delenv("DTVP_API_TOKEN", raising=False)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "dtvp",
            "knowledge",
            "--url",
            "http://dtvp.test",
            "legacy-archive-preview",
            "--project",
            "product/name",
            "--archive",
            str(path),
            "--offset",
            "1",
            "--limit",
            "5",
            *extra,
        ],
    )


def result():
    return {
        "preview_digest": "a" * 64,
        "total": 2,
        "statistics": {"versions": 2},
        "items": [
            {
                "entry_index": 2,
                "source_entry_id": "b" * 64,
                "normalization": {"status": "unsupported"},
                "losses": ["native_sbom_normalization_unsupported_no_upgrade_inferred"],
            }
        ],
        "limitations": ["Dry run only; no approvals or writes."],
        "next_offset": 2,
    }


@pytest.mark.parametrize("as_json", [False, True])
@respx.mock
def test_archive_cli_exact_bytes_header_bounded_chunks_and_paging(
    monkeypatch, tmp_path, capsys, as_json
):
    raw = b"not locally parsed ZIP\x00\r\n" * 10_000
    path = tmp_path / "source.zip"
    path.write_bytes(raw)
    argv(monkeypatch, path, *(["--json"] if as_json else []))
    native = Path.open
    reads = []

    class Tracked:
        def __init__(self, source):
            self.source = source

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.source.close()

        def fileno(self):
            return self.source.fileno()

        def read(self, size):
            reads.append(size)
            return self.source.read(size)

    monkeypatch.setattr(
        Path, "open", lambda self, *args, **kwargs: Tracked(native(self, *args, **kwargs))
    )
    route = respx.post(
        "http://dtvp.test/api/v1/projects/product%2Fname/migration/v1-archive/preview"
    ).mock(return_value=httpx.Response(200, json=result()))
    main()
    request = route.calls[0].request
    assert request.content == raw
    assert request.headers["content-type"] == "application/zip"
    assert dict(request.url.params) == {"offset": "1", "limit": "5"}
    assert reads and all(size == 64 * 1024 for size in reads)
    output = capsys.readouterr().out
    if as_json:
        assert json.loads(output) == result()
    else:
        assert "Source versions: 2" in output and "no approvals or writes" in output
        assert "Next offset: 2" in output and "unsupported" in output


@respx.mock
def test_archive_cli_rejects_oversized_file_before_open(monkeypatch, tmp_path, capsys):
    path = tmp_path / "oversized.zip"
    with path.open("wb") as stream:
        stream.truncate(MAX_COMPRESSED + 1)
    argv(monkeypatch, path, "--json")

    def forbidden(*args, **kwargs):
        pytest.fail("Oversized archive opened before local size admission")

    monkeypatch.setattr(Path, "open", forbidden)
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 1
    assert "regular file no larger than 64 MiB" in capsys.readouterr().err
    assert not respx.calls


@pytest.mark.parametrize("status", [401, 413, 422])
@respx.mock
def test_archive_cli_preserves_backend_failure(monkeypatch, tmp_path, capsys, status):
    path = tmp_path / "source.zip"
    path.write_bytes(b"unparsed input")
    argv(monkeypatch, path, "--json")
    route = respx.post(
        "http://dtvp.test/api/v1/projects/product%2Fname/migration/v1-archive/preview"
    ).mock(return_value=httpx.Response(status, json={"detail": "Archive rejected by backend"}))
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 1
    assert f"HTTP {status}: Archive rejected by backend" in capsys.readouterr().err
    assert len(route.calls) == 1


def test_archive_cli_requires_explicit_file_and_project(monkeypatch):
    monkeypatch.setattr(
        sys, "argv", ["dtvp", "knowledge", "legacy-archive-preview", "--project", "project"]
    )
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 2
