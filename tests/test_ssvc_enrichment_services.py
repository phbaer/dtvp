import asyncio
from copy import deepcopy

import httpx
import pytest

from dtvp.ssvc_enrichment_services import (
    SOURCES, SsvcEnrichmentService, parse_kev, parse_vulnrichment, verify_evidence,
)
from dtvp.ssvc_services import SsvcInput, new_record, preserve_record, write_record

CVE = "CVE-2024-25522"
OTHER = "CVE-2024-4947"
KEV = {"count": 1, "vulnerabilities": [{"cveID": CVE, "dateAdded": "2024-05-24"}]}


def adp(value="poc", cve=CVE):
    return {
        "cveMetadata": {"cveId": cve, "state": "PUBLISHED"},
        "containers": {"adp": [{
            "providerMetadata": {"orgId": SOURCES["vulnrichment"]["provider"]},
            "metrics": [{"other": {"type": "ssvc", "content": {
                "id": cve, "version": "2.0.3", "timestamp": "2024-05-24T15:01:21Z",
                "options": [{"Exploitation": value}, {"Automatable": "yes"}],
            }}}],
        }]},
    }


@pytest.fixture
def service(tmp_path, monkeypatch):
    monkeypatch.setenv("DTVP_SSVC_ENRICHMENT_ENABLED", "true")
    now = [1_800_000_000.0]
    calls = []
    responses = {"kev": KEV, CVE: adp(), OTHER: None}

    def handler(request):
        key = "kev" if request.url.host == "www.cisa.gov" else request.url.path.rsplit("/", 1)[-1][:-5]
        calls.append(request)
        response = responses[key]
        if isinstance(response, int):
            return httpx.Response(response)
        return httpx.Response(404 if response is None else 200, json=response, headers={"etag": f'"{key}"'})

    instance = SsvcEnrichmentService(str(tmp_path / "ssvc.sqlite3"), transport=httpx.MockTransport(handler), clock=lambda: now[0])
    return instance, now, calls, responses


@pytest.mark.asyncio
async def test_positive_kev_wins_and_signed_snapshot_is_documented(service):
    instance, _, calls, _ = service
    result = await instance.lookup([CVE.lower(), CVE])
    assert len(calls) == 2
    assert any("/2024/25xxx/" in str(call.url) for call in calls)
    assert result["auto_fill"]
    suggestion = result["suggestion"]
    assert suggestion["value"] == "A"
    assert suggestion["source"] == "CISA KEV"
    selection = SsvcInput(model="ssvc:DT_DP", version="1.0.0", rationale="Local context", answers={
        "ssvc:E:1.1.0": "A", "ssvc:EXP:1.0.1": "O", "ssvc:A:2.0.0": "Y", "ssvc:HI:2.0.2": "VH",
    }, exploitation_evidence=suggestion["token"])
    record = new_record(selection, "reviewer")
    assert record["priority"] == "Immediate"
    details = write_record("Reviewer notes", record)
    assert "SSVC priority: Immediate" in details
    assert "Exploitation evidence: CISA KEV" in details
    assert "Source assessment: 2024-05-24; checked:" in details
    assert "Reviewer notes" in details
    preserved = preserve_record(details, details)
    assert preserved == details
    assert preserved.count("[SSVC Summary]") == 1
    assert "SSVC priority" not in write_record(details, None)
    with pytest.raises(ValueError):
        verify_evidence(suggestion["token"], {"ssvc:E:1.1.0": "N"})
    with pytest.raises(ValueError):
        verify_evidence(suggestion["token"] + "tampered", selection.answers)


@pytest.mark.asyncio
async def test_hourly_shared_kev_lazy_daily_cve_and_force_cooldown(service):
    instance, now, calls, responses = service
    await instance.refresh_kev()
    assert len(calls) == 1  # Startup fetch does not enumerate Vulnrichment.
    await asyncio.gather(instance.lookup([CVE]), instance.lookup([CVE]))
    assert len(calls) == 2
    await instance.lookup([CVE], force=True)
    assert len(calls) == 2
    now[0] += 61
    responses["kev"] = responses[CVE] = 304
    result = await instance.lookup([CVE], force=True)
    assert len(calls) == 4
    assert all("if-none-match" in call.headers for call in calls[-2:])
    assert result["suggestion"]["value"] == "A"
    now[0] += 3601
    await instance.lookup([CVE])
    assert len(calls) == 5  # Only hourly KEV expires.
    now[0] += 86401
    await instance.lookup([CVE])
    assert len(calls) == 7
    reopened = SsvcEnrichmentService(instance.path, transport=instance.transport, clock=instance.clock)
    await reopened.lookup([CVE])
    assert len(calls) == 7  # Cache survives process/service restart.


@pytest.mark.asyncio
async def test_failure_retains_stale_evidence_without_autofilling(service):
    instance, now, _, responses = service
    original = (await instance.lookup([CVE]))["suggestion"]
    now[0] += 86401
    responses["kev"] = responses[CVE] = 503
    result = await instance.lookup([CVE])
    assert result["suggestion"]["stale"]
    assert result["suggestion"]["checked_at"] == original["checked_at"]
    assert not result["auto_fill"]
    assert all(source["status"] == "stale" for source in result["sources"])
    assert result["retry_after"] == 60


@pytest.mark.asyncio
async def test_absence_is_unknown_and_negative_cve_results_are_cached(service):
    instance, now, calls, responses = service
    result = await instance.lookup([OTHER])
    assert result["suggestion"] is None
    assert not result["auto_fill"]
    assert all(source["status"] == "not_found" for source in result["sources"])
    assert any("/2024/4xxx/" in str(call.url) for call in calls)
    now[0] += 61
    await instance.lookup([OTHER])
    assert len(calls) == 2
    responses[OTHER] = adp("none", OTHER)
    result = await instance.lookup([OTHER], force=True)
    assert result["suggestion"]["value"] == "N"
    assert result["auto_fill"]


@pytest.mark.asyncio
async def test_no_negative_suggestion_for_partially_known_aliases(service):
    instance, _, _, responses = service
    responses["kev"] = {**KEV, "vulnerabilities": [{"cveID": "CVE-2025-1234", "dateAdded": "2025-01-01"}]}
    responses[CVE] = adp("none")
    result = await instance.lookup([CVE, OTHER])
    assert result["suggestion"] is None


@pytest.mark.asyncio
async def test_poc_mapping_and_unavailable_kev_prevent_negative_autofill(service):
    instance, now, _, responses = service
    responses["kev"] = {**KEV, "vulnerabilities": [{"cveID": OTHER, "dateAdded": "2025-01-01"}]}
    result = await instance.lookup([CVE])
    assert result["suggestion"]["value"] == "P"
    assert result["auto_fill"]
    now[0] += 61
    responses["kev"] = 403
    result = await instance.lookup([CVE], force=True)
    assert result["suggestion"]["value"] == "P"
    assert not result["auto_fill"]


@pytest.mark.asyncio
async def test_disabled_empty_and_invalid_ids_never_fetch(service, monkeypatch):
    instance, _, calls, _ = service
    assert (await instance.lookup([]))["suggestion"] is None
    for ids in (["../../file"], [f"CVE-2024-{number:04d}" for number in range(21)]):
        with pytest.raises(ValueError):
            await instance.lookup(ids)
    monkeypatch.setenv("DTVP_SSVC_ENRICHMENT_ENABLED", "false")
    assert not (await instance.lookup([CVE], force=True))["enabled"]
    assert not calls


def test_parsers_reject_malformed_and_non_authoritative_records():
    assert parse_kev(KEV)[CVE]["value"] == "A"
    for document in ({"count": 0, "vulnerabilities": []}, {**KEV, "count": 2}):
        with pytest.raises(ValueError):
            parse_kev(document)
    original = adp()
    assert parse_vulnrichment(original, CVE)["value"] == "P"
    wrong_provider = deepcopy(original)
    wrong_provider["containers"]["adp"][0]["providerMetadata"]["orgId"] = "not-cisa"
    assert parse_vulnrichment(wrong_provider, CVE) is None
    for key, value in (("version", "99"), ("timestamp", "bad"), ("id", OTHER), ("options", [{"Exploitation": "maybe"}])):
        document = deepcopy(original)
        document["containers"]["adp"][0]["metrics"][0]["other"]["content"][key] = value
        with pytest.raises(ValueError):
            parse_vulnrichment(document, CVE)
    conflict = deepcopy(original)
    conflict["containers"]["adp"].extend(adp("active")["containers"]["adp"])
    with pytest.raises(ValueError):
        parse_vulnrichment(conflict, CVE)
    with pytest.raises(ValueError):
        parse_vulnrichment(original, OTHER)


@pytest.mark.asyncio
async def test_invalid_json_does_not_replace_good_snapshot(service):
    instance, now, _, responses = service
    await instance.lookup([CVE])
    now[0] += 61
    responses["kev"] = {"not": "a catalog"}
    responses[CVE] = {"not": "a CVE"}
    result = await instance.lookup([CVE], force=True)
    assert result["suggestion"]["stale"]
    assert result["suggestion"]["value"] == "A"
