"""Native non-US enrichment preserves exact upstream scope and immutable bytes."""

import copy
from types import SimpleNamespace

import httpx
import pytest
import respx

from dtvp.knowledge.advisory_sources import AdvisoryRefreshInput, collect_advisories
from dtvp.knowledge.workspace import load_workspace
from dtvp.non_us_advisories import EUVD_URL, JVN_URL, request_parameters
from tests.test_knowledge_advisory_documents import facts, heads, inventory
from tests.test_knowledge_advisory_documents import journal as source_journal
from tests.test_knowledge_advisory_sources import captured, data, publish

journal = source_journal
CVE = "CVE-2099-20001"
EUVD = "EUVD-2099-1234"
JVN = "JVNDB-2099-000001"
VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def euvd(identifier=CVE):
    return {
        "id": EUVD,
        "aliases": identifier + r"\nGHSA-aaaa-bbbb-cccc\n",
        "description": "Source-attributed enrichment",
        "baseScore": 0,
        "baseScoreVector": VECTOR,
        "baseScoreVersion": "3.1",
        "references": r"https://example.invalid/source\n",
        "assigner": "Example CNA",
        "epss": 0.7,
        "enisaIdVulnerability": [{"vulnerability": {"id": identifier}}],
    }


def jvn(identifier=JVN, *, found=True, status="0", count=None):
    values = (
        f"""<Vulinfo><VulinfoID>{identifier}</VulinfoID><VulinfoData>
      <VulinfoDescription><Overview>Source-attributed enrichment</Overview></VulinfoDescription>
      <Impact><Cvss version="3.1"><Base>0</Base><Vector>{VECTOR}</Vector></Cvss></Impact>
      <Related><RelatedItem type="advisory"><VulinfoID>{CVE}</VulinfoID>
      <URL>https://example.invalid/source</URL></RelatedItem></Related>
      </VulinfoData></Vulinfo>"""
        if found
        else ""
    )
    n = str(int(found)) if count is None else str(count)
    return f'''<VULDEF-Document xmlns="http://jvn.jp/vuldef/" xmlns:s="http://jvndb.jvn.jp/myjvn/Status" version="3.2">
      {values}<s:Status method="getVulnDetailInfo" feed="hnd" retCd="{status}" errCd="" errMsg=""
      vulnId="{identifier}" totalRes="{n}" totalResRet="{n}"/></VULDEF-Document>'''.encode()


def route(provider, identifier, *, raw=None, body=None, status=200):
    if raw is None:
        if provider == "jvn":
            raw = jvn(identifier)
        else:
            from dtvp.storage import canonical

            raw = canonical(euvd(identifier) if body is None else body)
    return respx.get(
        EUVD_URL if provider == "euvd" else JVN_URL, params=request_parameters(provider, identifier)
    ).mock(return_value=httpx.Response(status, content=raw))


@pytest.fixture
def settings():
    return SimpleNamespace(providers_enabled=["euvd", "jvn"])


@pytest.mark.parametrize("provider,identifier", [("euvd", CVE), ("euvd", EUVD), ("jvn", JVN)])
@respx.mock
def test_provider_publication_binds_original_bytes_and_never_expands_alias_coverage(
    journal, settings, bom, provider, identifier
):
    document = copy.deepcopy(bom)
    document["vulnerabilities"][0]["id"] = identifier
    initial = inventory(journal, document)
    response = route(provider, identifier)
    request = data(journal, [identifier], provider=provider)
    capture = captured(settings, journal, [identifier], provider)
    receipt = publish(journal, settings, request, capture)
    assert publish(journal, settings, request, copy.deepcopy(capture)) == receipt
    assert response.call_count == 1
    claim = next(claim for claim in facts(journal) if claim["identifier"] == identifier)
    assert claim["source"] == "connector:" + provider
    assert claim["advisory"]["ratings"][0]["score"] == 0
    assert len(capture["raw_artifact_shas"]) == 1
    raw = journal.objects.read(capture["raw_artifact_shas"][0])
    assert raw == response.calls[0].response.content
    assert initial != heads(journal)["1"]
    workspace = load_workspace(journal, heads(journal)["1"])
    assert all(not item["coverage"].get("approved") for item in workspace["items"])
    assert not any(item["vulnerability_id"] == "GHSA-aaaa-bbbb-cccc" for item in workspace["items"])
    assert capture["responses"][0]["parameters"] == request_parameters(provider, identifier)
    forged = copy.deepcopy(capture)
    forged["results"][0]["result"]["advisory"]["ratings"][0]["score"] = 10
    with pytest.raises(ValueError, match="differs"):
        publish(journal, settings, request, forged)


@pytest.mark.parametrize("provider,identifier", [("euvd", CVE), ("jvn", JVN)])
@respx.mock
def test_not_found_removes_only_provider_claim_and_retains_baseline(
    journal, settings, bom, provider, identifier
):
    document = copy.deepcopy(bom)
    document["vulnerabilities"][0]["id"] = identifier
    inventory(journal, document)
    route(provider, identifier)
    publish(
        journal,
        settings,
        data(journal, [identifier], provider=provider),
        captured(settings, journal, [identifier], provider),
    )
    route(
        provider,
        identifier,
        raw=b"" if provider == "euvd" else jvn(identifier, found=False),
        status=204 if provider == "euvd" else 200,
    )
    request = data(journal, [identifier], provider=provider, revision=2, request_id="missing")
    publish(journal, settings, request, captured(settings, journal, [identifier], provider))
    assert facts(journal) == []
    assert identifier in {
        item["vulnerability_id"] for item in load_workspace(journal, heads(journal)["1"])["items"]
    }


@pytest.mark.parametrize(
    "body",
    [euvd("CVE-2099-99999"), {}, [], {**euvd(), "aliases": [CVE]}, {**euvd(), "baseScore": True}],
)
@respx.mock
def test_euvd_mismatched_or_malformed_claim_fails_closed(settings, body):
    route("euvd", CVE, body=body)
    with pytest.raises(ValueError):
        collect_advisories(settings, "euvd", [CVE])


@pytest.mark.parametrize(
    "raw",
    [
        jvn("JVNDB-2099-000002"),
        jvn(status="1"),
        jvn(count=2),
        b"<VULDEF-Document/>",
        b'<!DOCTYPE x [<!ENTITY e "xx">]><VULDEF-Document>&e;</VULDEF-Document>',
    ],
)
@respx.mock
def test_jvn_failed_incomplete_unsafe_and_mismatched_xml_fails_closed(settings, raw):
    route("jvn", JVN, raw=raw)
    with pytest.raises(ValueError):
        collect_advisories(settings, "jvn", [JVN])


@respx.mock
def test_provider_specific_ids_fail_before_network(settings):
    for provider, identifier in [("jvn", CVE), ("euvd", JVN), ("nvd", EUVD)]:
        settings.providers_enabled = [provider]
        with pytest.raises(ValueError):
            collect_advisories(settings, provider, [identifier])
        with pytest.raises(ValueError):
            AdvisoryRefreshInput(
                request_id="invalid",
                provider=provider,
                identifiers=[identifier],
                expected_evidence=None,
                expected_versions={},
                revision=0,
            )
    assert not respx.calls


@pytest.mark.parametrize("provider,identifier", [("euvd", CVE), ("jvn", JVN)])
@respx.mock
def test_redirects_and_byte_limits_fail_closed(settings, monkeypatch, provider, identifier):
    response = route(provider, identifier)
    response.mock(
        return_value=httpx.Response(302, headers={"location": "https://attacker.invalid"})
    )
    with pytest.raises(httpx.HTTPStatusError):
        collect_advisories(settings, provider, [identifier])
    assert len(respx.calls) == 1
    route(provider, identifier)
    monkeypatch.setattr("dtvp.knowledge.advisory_sources.MAX_RESPONSE_BYTES", 10)
    with pytest.raises(ValueError, match="budget"):
        collect_advisories(settings, provider, [identifier])


@pytest.mark.parametrize(
    "change",
    [
        {"aliases": CVE + r"\nCVE-2099-99999\n"},
        {"enisaIdVulnerability": [{"vulnerability": {"id": "CVE-2099-99999"}}]},
        {"enisaIdVulnerability": [None]},
    ],
)
@respx.mock
def test_euvd_aggregates_cannot_transfer_group_scores_to_one_cve(settings, change):
    route("euvd", CVE, body={**euvd(), **change})
    with pytest.raises(ValueError, match="EUVD"):
        collect_advisories(settings, "euvd", [CVE])


@pytest.mark.parametrize("raw", [b"", jvn().replace(b"<Base>0</Base>", b"<Base>NaN</Base>")])
@respx.mock
def test_malformed_or_nonfinite_jvn_claim_fails_closed(settings, raw):
    route("jvn", JVN, raw=raw)
    with pytest.raises(ValueError):
        collect_advisories(settings, "jvn", [JVN])
