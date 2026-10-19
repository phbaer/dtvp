"""Publication CLI transports explicit declarations without inventing consent."""

import json
import sys

import httpx
import pytest
import respx

from dtvp.cli import main


def invoke(monkeypatch, tmp_path, metadata, *, apply=False):
    monkeypatch.delenv("DTVP_API_TOKEN", raising=False)
    archive = tmp_path / "reviewed.zip"
    archive.write_bytes(b"opaque archive bytes\x00")
    declaration = tmp_path / "declaration.json"
    declaration.write_bytes(metadata)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "dtvp",
            "knowledge",
            "--url",
            "http://dtvp.test",
            "legacy-archive-publication",
            "--project",
            "product/name",
            "--version",
            "release/test",
            "--archive",
            str(archive),
            "--input",
            str(declaration),
            *(["--apply"] if apply else []),
        ],
    )


@pytest.mark.parametrize("apply", [False, True])
@respx.mock
def test_explicit_metadata_exact_bytes_unicode_and_operation(monkeypatch, tmp_path, capsys, apply):
    metadata = {
        "request_id": "stable-request",
        "reason": "Prüfung 測試",
        "expected": None,
        "acknowledge_sanitized_export": False,
    }
    if apply:
        metadata["preview_digest"] = "a" * 64
    invoke(monkeypatch, tmp_path, json.dumps(metadata, ensure_ascii=False).encode(), apply=apply)
    operation = "apply" if apply else "preview"
    route = respx.post(
        f"http://dtvp.test/api/v1/projects/product%2Fname/versions/release%2Ftest/migration/v1-archive/{operation}"
    ).mock(return_value=httpx.Response(200, json={"result": "server-owned"}))
    main()
    request = route.calls[0].request
    assert request.content == b"opaque archive bytes\x00"
    assert request.headers["content-type"] == "application/zip"
    assert request.headers["x-dtvp-migration"].isascii()
    assert json.loads(request.headers["x-dtvp-migration"]) == metadata
    assert json.loads(capsys.readouterr().out) == {"result": "server-owned"}


@pytest.mark.parametrize(
    "metadata",
    [
        b"[]",
        b'{"a":1,"a":2}',
        b'{"a":NaN}',
        b'{"a":1e9999}',
        b" " * 8193,
        json.dumps({"a": "測" * 2000}, ensure_ascii=False).encode(),
    ],
)
@respx.mock
def test_invalid_or_expanded_oversized_metadata_never_uploaded(
    monkeypatch, tmp_path, capsys, metadata
):
    invoke(monkeypatch, tmp_path, metadata)
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 1
    assert not respx.calls
    assert capsys.readouterr().err


@pytest.mark.parametrize("status", [403, 409, 503])
@respx.mock
def test_backend_failure_is_not_publication_success(monkeypatch, tmp_path, capsys, status):
    invoke(monkeypatch, tmp_path, b'{"request_id":"retained"}', apply=True)
    route = respx.post(
        "http://dtvp.test/api/v1/projects/product%2Fname/versions/release%2Ftest/migration/v1-archive/apply"
    ).mock(return_value=httpx.Response(status, json={"detail": "Retry captured request"}))
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 1
    assert len(route.calls) == 1
    assert f"HTTP {status}" in capsys.readouterr().err
