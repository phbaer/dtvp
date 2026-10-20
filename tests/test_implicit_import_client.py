import json
import sys
from email import policy
from email.parser import BytesParser

import httpx
import pytest
import respx

from dtvp.cli import main


def import_args(monkeypatch, tmp_path, *, metadata=None, workspace=None):
    source = tmp_path / "sbom.json"
    source.write_bytes(b'\xef\xbb\xbf{ "components": [] }\r\n')
    config = tmp_path / "metadata.json"
    config.write_text(json.dumps(metadata if metadata is not None else {"request_id": "stable"}))
    argv = [
        "dtvp",
        "knowledge",
        "--url",
        "http://dtvp.test",
        "import-file",
        "--project",
        "Product / Name",
        "--version",
        "version / 1",
        "--file",
        str(source),
        "--metadata",
        str(config),
    ]
    if workspace is not None:
        argv.extend(["--workspace", workspace])
    monkeypatch.delenv("DTVP_API_TOKEN", raising=False)
    monkeypatch.setattr(sys, "argv", argv)
    return source, config


@pytest.mark.parametrize("created", [True, False])
@pytest.mark.parametrize("pin", ["omitted", None, "a" * 64])
@respx.mock
def test_import_resolves_product_without_changing_input(
    monkeypatch, tmp_path, capsys, created, pin
):
    metadata = {"request_id": "stable", "source": "supplier", "revision": 42}
    if pin != "omitted":
        metadata["expected"] = pin
    source, config = import_args(monkeypatch, tmp_path, metadata=metadata, workspace="workspace-1")
    metadata_text = json.dumps(metadata, indent=3) + "\n"
    config.write_text(metadata_text)
    resolver = respx.post("http://dtvp.test/api/v1/projects/resolve").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "resolved / id",
                "name": "Product / Name",
                "workspace_id": "workspace-1",
                "created": created,
            },
        )
    )
    upload = respx.post(
        "http://dtvp.test/api/v1/projects/resolved%20%2F%20id/versions/version%20%2F%201/files"
    ).mock(return_value=httpx.Response(201, json={"committed": True}))
    main()
    assert json.loads(resolver.calls[0].request.content) == {
        "project": "Product / Name",
        "workspace_id": "workspace-1",
    }
    assert respx.calls[0].request.url.path.endswith("/projects/resolve")
    request = upload.calls[0].request
    assert request.url.raw_path == (
        b"/api/v1/projects/resolved%20%2F%20id/versions/version%20%2F%201/files"
    )
    message = BytesParser(policy=policy.default).parsebytes(
        b"Content-Type: " + request.headers["Content-Type"].encode() + b"\r\n\r\n" + request.content
    )
    parts = {
        part.get_param("name", header="content-disposition"): part.get_payload(decode=True)
        for part in message.iter_parts()
    }
    assert parts["file"] == source.read_bytes()
    assert parts["metadata"] == metadata_text.encode()
    assert json.loads(parts["metadata"]) == metadata
    output = capsys.readouterr()
    assert json.loads(output.out) == {"committed": True}
    assert ("Created product Product / Name (resolved / id)" in output.err) == created


@pytest.mark.parametrize("status", [403, 409])
@respx.mock
def test_import_resolution_failure_never_uploads(monkeypatch, tmp_path, capsys, status):
    import_args(monkeypatch, tmp_path)
    resolver = respx.post("http://dtvp.test/api/v1/projects/resolve").mock(
        return_value=httpx.Response(status, json={"detail": "Cannot select product"})
    )
    with pytest.raises(SystemExit) as failure:
        main()
    assert failure.value.code == 1
    assert len(respx.calls) == 1
    assert json.loads(resolver.calls[0].request.content) == {"project": "Product / Name"}
    assert "Cannot select product" in capsys.readouterr().err


@pytest.mark.parametrize("problem", ["missing-file", "malformed-metadata", "array-metadata"])
@respx.mock
def test_import_invalid_local_input_never_resolves(monkeypatch, tmp_path, problem):
    source, config = import_args(monkeypatch, tmp_path)
    if problem == "missing-file":
        source.unlink()
    else:
        config.write_text("[" if problem == "malformed-metadata" else "[]")
    with pytest.raises(SystemExit) as failure:
        main()
    assert failure.value.code == 1
    assert not respx.calls
