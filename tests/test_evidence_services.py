import pytest

from dtvp.evidence_services import evidence_sources
from dtvp.ssvc_enrichment_services import SOURCES, SsvcEnrichmentService


@pytest.fixture
def cache(tmp_path):
    now = [1_800_000_000.0]
    service = SsvcEnrichmentService(str(tmp_path / "sources.sqlite3"), clock=lambda: now[0])
    return service, now


def test_unchecked_snapshot_is_read_only(cache, tmp_path):
    service, _ = cache
    before = list(tmp_path.iterdir())
    snapshot = service.filter_snapshot()
    assert list(tmp_path.iterdir()) == before
    assert evidence_sources({"id": "CVE-2026-1234"}, snapshot) == ["NOT_CHECKED"]
    assert evidence_sources({"id": "GHSA-unknown"}, snapshot) == ["NO_CVE"]
    assert service.filter_snapshot() is snapshot


def test_aliases_match_sources_without_saved_ssvc(cache):
    service, now = cache
    service._cache("kev", {"checked": now[0], "data": {"CVE-2026-1234": {"value": "A"}}})
    service._cache("CVE-2026-5678", {"checked": now[0], "data": {"value": "N"}})
    group = {"id": "GHSA-other", "aliases": ["cve-2026-1234", "CVE-2026-5678", "CVE-2026-1234"]}
    assert evidence_sources(group, service.filter_snapshot()) == ["KEV", "CISA_SSVC", "NOT_CHECKED"]
    service._cache("CVE-2026-1234", {"checked": now[0], "data": None})
    assert evidence_sources(group, service.filter_snapshot()) == ["KEV", "CISA_SSVC"]


def test_no_data_requires_complete_fresh_negative_coverage(cache):
    service, now = cache
    group = {"id": "CVE-2026-1234", "aliases": ["CVE-2026-5678"]}
    service._cache("kev", {"checked": now[0], "data": {}})
    service._cache(group["id"], {"checked": now[0], "data": None})
    assert evidence_sources(group, service.filter_snapshot()) == ["NOT_CHECKED"]
    service._cache(group["aliases"][0], {"checked": now[0], "data": None})
    snapshot = service.filter_snapshot()
    assert evidence_sources(group, snapshot) == ["NO_DATA"]
    now[0] += SOURCES["kev"]["ttl_seconds"]
    expired = service.filter_snapshot()
    assert expired["revision"] != snapshot["revision"]
    assert evidence_sources(group, expired) == ["STALE"]


def test_failed_refresh_keeps_positive_matches(cache):
    service, now = cache
    service._cache("kev", {"checked": now[0], "data": {"CVE-2026-1234": {"value": "A"}}, "error": "offline"})
    service._cache("CVE-2026-1234", {"error": "offline"})
    assert evidence_sources({"id": "CVE-2026-1234"}, service.filter_snapshot()) == ["KEV", "STALE", "UNAVAILABLE"]


@pytest.mark.parametrize("invalid", ["not a dictionary", {"checked": "not a timestamp"}])
def test_corrupt_cache_reports_unavailable(cache, invalid):
    service, _ = cache
    service._cache("kev", invalid)
    snapshot = service.filter_snapshot()
    assert evidence_sources({"id": "CVE-2026-1234"}, snapshot) == ["UNAVAILABLE"]
    assert service.filter_snapshot() is snapshot
