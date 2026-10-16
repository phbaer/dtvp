"""Explicit bulk mirroring checks META first and never activates partial downloads."""

import httpx
import pytest
import respx

from dtvp.knowledge.cpe_catalog import ARCHIVE_URL, META_URL, Catalog
from tests.test_cpe_catalog import archive


@respx.mock
def test_mirror_captures_exact_complete_archive_and_unchanged_meta_avoids_download(tmp_path):
    source, meta = archive(tmp_path)
    metadata = respx.get(META_URL).mock(return_value=httpx.Response(200, content=meta.read_bytes()))
    download = respx.get(ARCHIVE_URL).mock(
        return_value=httpx.Response(200, content=source.read_bytes())
    )
    catalog = Catalog(tmp_path / "catalog")
    result = catalog.mirror()
    assert result["changed"] and result["records"] == 2
    assert metadata.call_count == 2 and download.call_count == 1
    assert catalog.verify()["verified"]
    unchanged = catalog.mirror()
    assert not unchanged["changed"] and unchanged["generation"] == result["generation"]
    assert metadata.call_count == 3 and download.call_count == 1
    assert all(str(call.request.url) in {META_URL, ARCHIVE_URL} for call in respx.calls)


@respx.mock
def test_meta_race_during_download_never_initializes_catalog(tmp_path):
    source, meta = archive(tmp_path)
    before = meta.read_bytes()
    metadata = respx.get(META_URL).mock(
        side_effect=[
            httpx.Response(200, content=before),
            httpx.Response(200, content=before.replace(b"2099-01-01", b"2099-01-02")),
        ]
    )
    respx.get(ARCHIVE_URL).mock(return_value=httpx.Response(200, content=source.read_bytes()))
    catalog = Catalog(tmp_path / "absent")
    with pytest.raises(ValueError, match="changed during"):
        catalog.mirror()
    assert metadata.call_count == 2 and not catalog.root.exists()


@pytest.mark.parametrize("case", ["redirect", "timeout", "truncated", "compressed-transport"])
@respx.mock
def test_mirror_protocol_failures_never_activate_a_generation(tmp_path, case):
    source, meta = archive(tmp_path)
    metadata = respx.get(META_URL).mock(return_value=httpx.Response(200, content=meta.read_bytes()))
    if case == "redirect":
        metadata.mock(
            return_value=httpx.Response(
                302, headers={"location": "https://attacker.invalid/catalog"}
            )
        )
    elif case == "timeout":
        metadata.mock(side_effect=httpx.ReadTimeout("synthetic timeout"))
    elif case == "truncated":
        respx.get(ARCHIVE_URL).mock(
            return_value=httpx.Response(200, content=source.read_bytes()[:-10])
        )
    else:
        # Deliberately encoded outer transport is rejected; archive bytes must stay exact.
        import gzip

        respx.get(ARCHIVE_URL).mock(
            return_value=httpx.Response(
                200,
                content=gzip.compress(source.read_bytes()),
                headers={"Content-Encoding": "gzip"},
            )
        )
    catalog = Catalog(tmp_path / "catalog")
    with pytest.raises((ValueError, httpx.HTTPError)):
        catalog.mirror()
    assert catalog.current() is None
    assert all("attacker" not in str(call.request.url) for call in respx.calls)
