import json
from pathlib import Path

import httpx
import pytest
import respx

from dtvp.parsers import identity, parse
from dtvp.providers import CIRCL, OSV
from dtvp.storage import Artifacts

FIXTURES = Path(__file__).resolve().parent.parent / "playground/fixtures"


def test_spdx_and_xml_and_unsafe_xml():
    parsed = parse((FIXTURES / "release.spdx.json").read_bytes())
    assert parsed["format"] == "spdx-2.3-json"
    assert parsed["components"][0]["purl"] == "pkg:npm/demo-utility@3.0.0"
    assert parsed["losses"]
    xml = b'<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1"><components><component type="library" bom-ref="one"><name>demo</name><version>1.0</version></component></components></bom>'
    assert parse(xml)["components"][0]["name"] == "demo"
    with pytest.raises(Exception):
        parse(b'<!DOCTYPE bom [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><bom>&xxe;</bom>')


def test_identity_keeps_qualifiers_hashes_and_unversioned_sources():
    a = {"bom-ref": "a", "purl": "pkg:npm/demo@1.0", "name": "demo", "version": "1.0"}
    b = {**a, "purl": "pkg:npm/demo@1.0?arch=arm"}
    assert identity(a, "one") != identity(b, "one")
    assert identity(a, "one") == identity(a, "two")
    a["purl"] = "pkg:npm/demo"
    assert identity(a, "one") != identity(a, "two")


@respx.mock
def test_osv_pagination_and_unsupported_variants():
    route = respx.post("https://api.osv.dev/v1/query").mock(
        side_effect=[
            httpx.Response(
                200,
                json={
                    "vulns": [{"id": "OSV-DEMO", "aliases": ["CVE-2099-20001"]}],
                    "next_page_token": "next",
                },
            ),
            httpx.Response(200, json={"vulns": []}),
        ]
    )
    with httpx.Client() as client:
        matcher = OSV(client)
        result = matcher.query("pkg:npm/demo@1.0")
        assert result["status"] == "checked"
        assert len(result["advisories"]) == 1
        assert json.loads(route.calls[1].request.content)["page_token"] == "next"
        assert matcher.query("pkg:npm/demo@1.0?arch=arm")["status"] == "unsupported"
        assert matcher.query("pkg:npm/demo")["status"] == "unsupported"


@respx.mock
def test_circl_keeps_publisher_lineage():
    respx.get("https://vulnerability.circl.lu/api/vulnerability/CVE-2099-20001").mock(
        return_value=httpx.Response(
            200,
            json={
                "containers": {
                    "cna": {
                        "providerMetadata": {"shortName": "original-cna"},
                        "descriptions": [{"lang": "en", "value": "Synthetic"}],
                    }
                }
            },
        )
    )
    with httpx.Client() as client:
        result = CIRCL(client).get("CVE-2099-20001")
    assert result["publisher"]["shortName"] == "original-cna"
    assert result["kind"] == "advisory"


def test_artifact_integrity_and_traversal(tmp_path):
    store = Artifacts(tmp_path)
    sha = store.put(b"synthetic")
    assert store.put(b"synthetic") == sha
    assert store.read(sha) == b"synthetic"
    with pytest.raises(ValueError):
        store.read("../passwd")
    store.path(sha).write_bytes(b"tampered")
    with pytest.raises(ValueError):
        store.read(sha)
